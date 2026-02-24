from decimal import Decimal
from typing import Literal, Dict
from pydantic import BaseModel, field_validator


def check_split_perc_sum(value: Dict[str, Decimal]) -> Dict[str, Decimal]:
    if sum(value.values()) == 1:
        return value
    raise ValueError(f"{value} sum of split parts should be 1")


AmlScore = Decimal
PayoutRatio = Decimal


class CryptoSplitConfig(BaseModel):
    addresses: Dict[str, PayoutRatio]
    min_check_amount: Decimal

    @field_validator("addresses", mode="after")
    @classmethod
    def validate_addresses(cls, value: Dict[str, Decimal]) -> Dict[str, Decimal]:
        return check_split_perc_sum(value)


class RegularSplitConfig(BaseModel):
    state: Literal["disabled", "enabled"]
    cryptos: Dict[str, CryptoSplitConfig]


class AmlRiskConfig(BaseModel):
    min_value: AmlScore
    max_value: AmlScore
    addresses: Dict[str, PayoutRatio]

    @field_validator("addresses", mode="after")
    @classmethod
    def validate_addresses(cls, value: Dict[str, Decimal]) -> Dict[str, Decimal]:
        return check_split_perc_sum(value)


class AmlCryptoConfig(BaseModel):
    min_check_amount: Decimal
    risk_scores: Dict[str, AmlRiskConfig]

    @field_validator("risk_scores", mode="after")
    @classmethod
    def validate_scores(
        cls, value: Dict[str, AmlRiskConfig]
    ) -> Dict[str, AmlRiskConfig]:
        intervals = sorted(value.values(), key=lambda x: x.min_value)
        int_start = intervals[0].min_value
        int_end = intervals[-1].max_value
        if int_start != 0 or int_end != 1:
            raise ValueError(
                f"risk scores should cover interval [0; 1], got [{int_start}; {int_end}]"
            )
        for config in value.values():
            if config.min_value > config.max_value:
                raise ValueError(f"min > max in {config}")
        return value


class AmlSplitConfig(BaseModel):
    state: Literal["disabled", "enabled"]
    access_id: str
    access_key: str
    access_point: str
    flow: Literal["fast", "accurate", "advanced"]
    cryptos: Dict[str, AmlCryptoConfig]


class ExternalDrain(BaseModel):
    regular_split: RegularSplitConfig
    aml_check: AmlSplitConfig

from ..config import Config
from .base import Detector
from .brute_force import BruteForceDetector
from .new_source import NewSourceDetector
from .off_hours import OffHoursDetector
from .password_spray import PasswordSprayDetector
from .slow_brute import SlowBruteDetector


def default_detectors(config: Config) -> list:
    return [
        BruteForceDetector(config),
        PasswordSprayDetector(config),
        SlowBruteDetector(config),
        NewSourceDetector(config),
        OffHoursDetector(config),
    ]


__all__ = [
    "Detector",
    "BruteForceDetector",
    "PasswordSprayDetector",
    "SlowBruteDetector",
    "NewSourceDetector",
    "OffHoursDetector",
    "default_detectors",
]

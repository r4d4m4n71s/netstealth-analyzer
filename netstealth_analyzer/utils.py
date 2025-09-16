"""Utility functions for Stealth Analyzer."""

import logging
import yaml
from pathlib import Path
from typing import Any, Dict

from .models import AnalysisConfig


def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Set up logging for the analyzer."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


def load_config(config_path: Path) -> AnalysisConfig:
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        return AnalysisConfig(**config_data)
    except Exception as e:
        raise ValueError(f"Failed to load config from {config_path}: {e}")


def save_config(config: AnalysisConfig, config_path: Path) -> None:
    """Save configuration to YAML file."""
    config_dict = config.model_dump()
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, indent=2)

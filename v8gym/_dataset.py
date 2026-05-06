from __future__ import annotations

import importlib.resources
from functools import lru_cache
from typing import Any

import pandas as pd


@lru_cache(maxsize=1)
def _load() -> pd.DataFrame:
    data_path = importlib.resources.files("v8gym.data").joinpath("bugs_report.feather")
    with importlib.resources.as_file(data_path) as p:
        return pd.read_feather(p)


def get_task(task_id: int) -> dict[str, Any]:
    df = _load()
    rows = df[df["id"] == task_id]
    if rows.empty:
        raise KeyError(f"Task id {task_id!r} not found in dataset")
    return rows.iloc[0].to_dict()


def list_tasks() -> pd.DataFrame:
    return _load()[["id", "crbug_id", "summary", "build_type", "exit_code", "commit"]].copy()

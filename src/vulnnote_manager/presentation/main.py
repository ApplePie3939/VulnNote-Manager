"""ホーム画面の経路。"""

from __future__ import annotations

from flask import Blueprint, render_template

main_blueprint = Blueprint("main", __name__)


@main_blueprint.get("/")
def index() -> str:
    """データ登録前にも表示できる最小ホーム画面を返す。"""

    return render_template("index.html")

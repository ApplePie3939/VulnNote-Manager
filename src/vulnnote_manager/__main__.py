"""``python -m vulnnote_manager`` 用の起動処理。"""

from __future__ import annotations

import sys

from . import create_app
from .config import ConfigurationError, load_settings


def main() -> int:
    """安全な既定値でローカル開発サーバーを起動する。"""

    try:
        settings = load_settings()
        app = create_app(settings=settings)
    except ConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 2

    app.run(
        host=settings.host,
        port=settings.port,
        debug=False,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

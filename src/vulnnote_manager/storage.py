"""ファイル・SQLite保存失敗の利用者向け変換。"""

from __future__ import annotations

import errno


class StorageOperationError(RuntimeError):
    """保存状態と対処を安全に説明できる業務例外。"""

    def __init__(self, message: str, *, data_saved: bool = False) -> None:
        super().__init__(message)
        self.data_saved = data_saved


def translate_storage_error(error: OSError, *, operation: str) -> StorageOperationError:
    """OS依存の保存エラーを秘密情報を含まない日本語へ変換する。"""

    if error.errno == errno.ENOSPC:
        message = (
            f"{operation}できませんでした。データ保存先の空き容量が不足しています。"
            "空き容量を確保してから、もう一度操作してください。"
        )
    elif error.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
        message = (
            f"{operation}できませんでした。データ保存先へ書き込む権限がありません。"
            "保存先の権限または VULNNOTE_DATA_DIR を確認してください。"
        )
    else:
        message = (
            f"{operation}中に保存先のエラーが発生しました。データは保存されていません。"
            "保存先が利用可能か確認して、もう一度操作してください。"
        )
    return StorageOperationError(message, data_saved=False)

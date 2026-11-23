from fastapi import HTTPException, status


def credentials_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="用户名或密码错误",
        headers={"WWW-Authenticate": "Bearer"},
    )

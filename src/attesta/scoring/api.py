"""HTTP API for CI: POST /v1/score. Bearer-token auth; serve behind TLS (see cli serve)."""
import hmac
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from attesta.scoring.errors import (
    ArchiveError, ConfigError, FetchError, InvalidTarget, SubmitError)
from attesta.scoring.service import ScoringService


class ScoreRequest(BaseModel):
    ecosystem: str = Field(max_length=16)
    package: str = Field(max_length=214)
    version: str = Field(max_length=64)
    run_id: str = Field("", max_length=100)  # CI run identifier, informational prefix only
    dry_run: bool = False


def create_api(service: ScoringService, token: str) -> FastAPI:
    if not token:
        raise ConfigError("an API token is required")
    app = FastAPI(title="Attesta scoring service")

    def require_token(authorization: str = Header(default="")) -> None:
        supplied = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/score", dependencies=[Depends(require_token)])
    def score(req: ScoreRequest) -> dict[str, Any]:
        try:
            result = service.score(req.ecosystem, req.package, req.version,
                                   run_hint=req.run_id, dry_run=req.dry_run)
        except InvalidTarget as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (FetchError, ArchiveError, SubmitError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except ConfigError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return result.summary()

    return app

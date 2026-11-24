from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JAVA_SOURCE = PROJECT_ROOT / "src" / "java" / "main" / "ValidadorCliWrapper.java"
DEFAULT_BUILD_DIR = PROJECT_ROOT / "build"
DEFAULT_JAVAC_EXE = Path(r"C:\Program Files\Java\jdk-17\bin\javac.exe")
DEFAULT_JAVA_EXE = Path(r"C:\Program Files\Java\jdk-17\bin\java.exe")
DEFAULT_FIRMAEC_JAR = Path(r"C:\Program Files\FirmaEC\cliente-jar-with-dependencies.jar")


def _extraer_json_de_stdout(stdout_text: str) -> str:
    inicio = stdout_text.find("{")
    fin = stdout_text.rfind("}")
    if inicio == -1 or fin == -1 or fin < inicio:
        raise ValueError(f"No se encontro un objeto JSON en stdout. Salida: {stdout_text.strip()!r}")
    return stdout_text[inicio : fin + 1]


def compilar_wrapper(
    java_source: Path = DEFAULT_JAVA_SOURCE,
    build_dir: Path = DEFAULT_BUILD_DIR,
    javac_exe: Path = DEFAULT_JAVAC_EXE,
    firmaec_jar: Path = DEFAULT_FIRMAEC_JAR,
    forzar: bool = False,
) -> Path:
    if not java_source.exists():
        raise FileNotFoundError(f"No se encontro {java_source}")
    if not javac_exe.exists():
        raise FileNotFoundError(f"No se encontro javac en {javac_exe}")
    if not firmaec_jar.exists():
        raise FileNotFoundError(f"No se encontro el JAR de FirmaEC en {firmaec_jar}")

    build_dir.mkdir(parents=True, exist_ok=True)
    clase_compilada = build_dir / "ValidadorCliWrapper.class"

    necesita_compilar = (
        forzar
        or not clase_compilada.exists()
        or java_source.stat().st_mtime > clase_compilada.stat().st_mtime
    )

    if necesita_compilar:
        cmd = [
            str(javac_exe),
            "-encoding",
            "UTF-8",
            "-cp",
            str(firmaec_jar),
            "-d",
            str(build_dir),
            str(java_source),
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode != 0:
            detalle = proc.stderr.strip() or proc.stdout.strip() or "Error desconocido al compilar"
            raise RuntimeError(f"Fallo al compilar ValidadorCliWrapper.java: {detalle}")

    return build_dir


def validar_documento(
    documento_path: str | Path,
    url_ocsp: str | None = None,
    url_crl: str | None = None,
    forzar_compilacion: bool = False,
    java_exe: Path = DEFAULT_JAVA_EXE,
    javac_exe: Path = DEFAULT_JAVAC_EXE,
    firmaec_jar: Path = DEFAULT_FIRMAEC_JAR,
    java_source: Path = DEFAULT_JAVA_SOURCE,
    build_dir: Path = DEFAULT_BUILD_DIR,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    doc = Path(documento_path).resolve()
    if not doc.exists():
        raise FileNotFoundError(f"No se encontro el documento: {doc}")
    if not java_exe.exists():
        raise FileNotFoundError(f"No se encontro java en {java_exe}")

    clases_dir = compilar_wrapper(
        java_source=java_source,
        build_dir=build_dir,
        javac_exe=javac_exe,
        firmaec_jar=firmaec_jar,
        forzar=forzar_compilacion,
    )

    classpath = f"{clases_dir};{firmaec_jar}"
    cmd = [
        str(java_exe),
        "-Djava.awt.headless=true",
        "-cp",
        classpath,
        "ValidadorCliWrapper",
        str(doc),
    ]

    if url_ocsp or url_crl:
        cmd.append(url_ocsp if url_ocsp else "")
    if url_crl:
        cmd.append(url_crl)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )

    if proc.returncode != 0:
        detalle = proc.stderr.strip() or proc.stdout.strip() or "Sin mensaje de error"
        raise RuntimeError(f"Fallo en ValidadorCliWrapper (exit={proc.returncode}): {detalle}")

    salida = proc.stdout.strip()
    if not salida:
        err_msg = proc.stderr.strip()
        raise ValueError(
            "ValidadorCliWrapper no emitio contenido JSON en stdout."
            + (f" STDERR: {err_msg}" if err_msg else "")
        )

    json_limpio = _extraer_json_de_stdout(salida)
    return json.loads(json_limpio)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Valida firmas de documentos PDF/XML usando el motor de FirmaEC sin interfaz grafica."
    )
    parser.add_argument("documento", help="Ruta al archivo .pdf o .xml firmado")
    parser.add_argument("--ocsp", dest="url_ocsp", default=None, help="URL OCSP opcional")
    parser.add_argument("--crl", dest="url_crl", default=None, help="URL CRL opcional")
    parser.add_argument("--compile", action="store_true", help="Fuerza recompilar ValidadorCliWrapper.java")
    parser.add_argument("--timeout", type=int, default=120, help="Tiempo maximo de espera en segundos")
    args = parser.parse_args()

    try:
        resultado = validar_documento(
            documento_path=args.documento,
            url_ocsp=args.url_ocsp,
            url_crl=args.url_crl,
            forzar_compilacion=args.compile,
            timeout_seconds=args.timeout,
        )
        print(json.dumps(resultado, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
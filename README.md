# ValidadorCliWrapper (FICA)

Automatización de validación de firmas digitales (PDF/XML) con FirmaEC, Java 17 y Python.

## Requisitos previos
- Java JDK 17 instalado (`C:\Program Files\Java\jdk-17\bin`)
- FirmaEC instalado (JAR: `C:\Program Files\FirmaEC\cliente-jar-with-dependencies.jar`)
- Python 3.10+

## Estructura del proyecto
- `src/java/`: Código fuente Java (`ValidadorCliWrapper.java`)
- `src/python/`: Orquestador Python (`validador_firmaec.py`)
- `docs/`: Documentación y reglas de auditoría
- `tests/`: Archivos de prueba pequeños (los pesados van en `lotes/`)
- `build/`: Carpeta temporal de compilación (ignorada en Git)

## Uso rápido
```bash
# Compilar y ejecutar el validador sobre un archivo
python src/python/validador_firmaec.py ruta/al/archivo.pdf
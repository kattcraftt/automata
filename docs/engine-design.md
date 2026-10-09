# Engine Design

## Overview
Automata is a high-performance firmware analysis engine.

## Module Descriptions
- **engine**: C and Assembly core for rapid block classification and parsing.
- **ml**: Machine learning models and training scripts.
- **platform**: FastAPI and Celery-based backend for scalable analysis workflows.

## Data Flow
1. Firmware is uploaded to the Platform API.
2. Celery worker picks up the task and streams the firmware to the engine.
3. Engine performs entropy, signature, and ML-based analysis.
4. Results are stored in the PostgreSQL database.

## ML/Platform Integration Points
- Engine invokes ML classifier for block classification.
- Platform API provides results view and triggers engine tasks.

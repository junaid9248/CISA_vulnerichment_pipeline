#!/bin/bash

allyears=$(python -c 'from src.get_years import get_years; print(json.dumps(get_years()))') 
echo 'allyears=$YEARS' >> "$GITHUB_OUTPUT"
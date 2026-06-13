Run the test suite and report failures only.

```bash
docker-compose exec web pytest apps/ -x -q --tb=short 2>&1 | tail -40
```

Fix any failures before continuing. Do not summarise passing tests.
# PyQuality

`pyquality.py` agrega checks de qualidade para Python em um unico CLI. O foco agora e ficar local e simples: manter os analisadores Python no proprio script.

## Ferramentas

- `pylint`
- `flake8`
- `ruff`
- `prospector`
- `bandit`
- `semgrep`
- `radon`
- `vulture`
- `mypy`

## Instalar

```bash
pip install -r require.txt
```

## Uso

```bash
python3 pyquality.py src/
python3 pyquality.py src/ --json
python3 pyquality.py src/ -v
python3 pyquality.py src/ --reports-dir docs/quality
python3 pyquality.py src/ --prospector-strictness high
```

## Semgrep

Por padrao o script roda `semgrep` com uma ruleset local embutida no proprio `pyquality.py`.
Nao depende de registry externa nem de API.

Para trocar:

```bash
python3 pyquality.py src/ --semgrep-config rules/semgrep.yml
python3 pyquality.py src/ --semgrep-config /caminho/absoluto/regras.yml
```

## Observacoes

- `ruff` entra como camada rapida de lint moderno, sem remover `pylint` nem `flake8`.
- `prospector` entra como agregador extra; ele nao substitui o resto do pipeline, ele soma outra visao consolidada.
- `semgrep` complementa `bandit` com regras locais de bug/security por padrao.
- Se alguma ferramenta nao estiver instalada, o PyQuality nao quebra a execucao inteira; ele registra o erro no relatorio.

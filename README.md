# NetScanner

NetScanner e uma CLI Python para auditoria defensiva de rede em Linux e macOS.

Ela valida o escopo antes de tocar na rede, monta argumentos seguros para o Nmap, registra logs com Loguru e exporta resultados em texto, JSON ou CSV. A ideia e ser simples de revisar, previsivel para operar e honesta quando falta alguma dependencia.

## O que ela faz

- Gera plano de scan sem executar nada.
- Executa Nmap em alvos autorizados.
- Valida alvo, portas e modo de scan com Pydantic.
- Usa Loguru para console humano e arquivo estruturado.
- Exporta resultado em `text`, `json` ou `csv`.
- Exige confirmacao explicita de autorizacao antes de rodar scan real.

## Requisitos

- Linux ou macOS
- Python 3.10+
- Nmap instalado no sistema

Instalacao do Nmap:

```bash
# macOS
brew install nmap

# Debian/Ubuntu
sudo apt-get update
sudo apt-get install nmap
```

## Instalacao do projeto

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Uso rapido

Verificar ambiente:

```bash
netscanner check
```

Gerar um plano sem executar scan:

```bash
netscanner plan --target 192.168.1.10 --ports 22,80,443 --mode service
```

Executar um scan autorizado:

```bash
netscanner scan \
  --target 192.168.1.10 \
  --ports 22,80,443 \
  --mode service \
  --format json \
  --output output/scan.json \
  --i-have-authorization
```

## Modos

- `tcp`: TCP connect scan, funciona sem privilegio elevado.
- `service`: TCP connect com deteccao leve de servico.
- `syn`: usa SYN scan apenas com privilegio. Sem privilegio, cai para TCP connect e registra aviso.

## Exemplos

Veja `examples/` para saidas de plano e relatorio.

## Nota de seguranca

Use apenas em redes e sistemas onde voce tem autorizacao. A CLI bloqueia scan real sem `--i-have-authorization`, mas a responsabilidade pelo escopo continua sendo do operador.

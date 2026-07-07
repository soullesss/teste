# Security

NetScanner e uma ferramenta defensiva. Ela foi desenhada para auditoria autorizada em Linux e macOS, com alguns freios simples para evitar uso acidental fora de escopo.

## Guardrails atuais

- `scan` exige `--i-have-authorization`.
- `plan` mostra o comando Nmap antes de executar qualquer coisa.
- `syn` cai para TCP connect quando nao ha privilegio elevado.
- Entrada de alvo e portas passa por validacao antes da execucao.
- Logs usam Loguru com arquivo estruturado e retencao curta.

## Uso aceitavel

- Laboratorios proprios.
- Redes internas com autorizacao escrita.
- Validacao de exposicao de servicos em ambientes controlados.
- Evidencia tecnica para hardening e inventario.

## Fora de escopo

- Scan de redes de terceiros sem permissao.
- Coleta ou armazenamento de credenciais.
- Tentativa de contornar autenticacao, rate limit ou controles de acesso.
- Qualquer fluxo de exploracao automatizada.

## Reportando problema

Se voce encontrar uma falha de seguranca neste projeto, abra uma issue descrevendo impacto, versao e passos de reproducao em ambiente controlado. Nao inclua tokens, credenciais, IPs sensiveis ou dados pessoais.

# Use a imagem oficial do Python 3.10 slim como base.
# A tag "slim" oferece uma imagem menor sem pacotes desnecessários.
FROM python:3.10-slim

# Define o diretório de trabalho dentro do container.
# Todas as instruções subsequentes serão executadas a partir daqui.
WORKDIR /app

# Copia o arquivo de dependências para o diretório de trabalho.
# É uma boa prática copiar apenas o requirements.txt primeiro para aproveitar o cache do Docker.
COPY requirements.txt .

# Instala as dependências especificadas no arquivo requirements.txt.
# O --no-cache-dir garante que o cache do pip não seja armazenado na imagem final, economizando espaço.
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código da sua aplicação para o diretório de trabalho.
COPY . .

# Expõe a porta 8000, que é a porta padrão que o Uvicorn usará.
EXPOSE 8000

# Define o comando para rodar a aplicação quando o container iniciar.
# O 'gunicorn' é o servidor de produção que rodará o 'uvicorn', proporcionando um desempenho melhor e mais seguro.
# O '-w 4' define 4 workers, que é uma boa prática para a maioria das CPUs.
# O '--bind 0.0.0.0:8000' faz com que o servidor escute em todas as interfaces de rede na porta 8000.
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "main:app"]
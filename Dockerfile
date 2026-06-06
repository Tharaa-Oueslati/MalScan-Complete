FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs/samples config dashboard/static

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py", "--watch", "logs/samples", "--port", "5000"]

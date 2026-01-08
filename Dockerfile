# ====================
# Backend Dockerfile (Secure / Production-friendly)
# ====================

# -------- Stage 1: Build --------
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Copiar apenas o necessário para cache de dependências
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

# Corrige permissão do mvnw (Windows -> Linux)
RUN chmod +x mvnw

# Baixar dependências (layer de cache)
RUN ./mvnw -B -q dependency:go-offline

# Copiar código fonte
COPY src ./src

# Build do projeto (pula testes para acelerar)
RUN ./mvnw -B -q clean package -DskipTests


# -------- Stage 2: Runtime --------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# wget para healthcheck
RUN apk add --no-cache wget

# Criar usuário não-root (melhor prática)
RUN addgroup -S app && adduser -S app -G app

# Diretório para uploads (com permissões seguras)
RUN mkdir -p /app/uploads \
  && chown -R app:app /app \
  && chmod 755 /app/uploads

# Copiar JAR gerado no build
COPY --from=build /app/target/*.jar /app/app.jar

# Porta padrão (a plataforma pode sobrescrever via variável PORT)
ENV PORT=8080

# Expor porta (informativo)
EXPOSE 8080

# Health check: requer actuator em /actuator/health
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/actuator/health || exit 1

# Rodar como usuário não-root
USER app

# Start: respeita PORT (muito importante em nuvem)
ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT} -Djava.security.egd=file:/dev/./urandom -jar /app/app.jar"]

# -------- Stage 1: Build --------
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app

COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

# Permissão pro wrapper
RUN chmod +x mvnw

# Cache de dependências
RUN ./mvnw -B -q dependency:go-offline

# Copia o projeto inteiro
COPY . .

# IMPORTANTE: o COPY acima pode sobrescrever o mvnw e perder permissão
RUN chmod +x mvnw

# Build
RUN ./mvnw -B -q clean package -DskipTests


# -------- Stage 2: Runtime --------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN apk add --no-cache wget
RUN addgroup -S app && adduser -S app -G app

RUN mkdir -p /app/uploads \
  && chown -R app:app /app \
  && chmod 755 /app/uploads

COPY --from=build /app/target/*.jar /app/app.jar

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=10 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/actuator/health || exit 1

USER app
ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT} -Djava.security.egd=file:/dev/./urandom -jar /app/app.jar"]

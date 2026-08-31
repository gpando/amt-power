

# Ejecución directa
AMT_PASSWORD="XXXX" go run main.go -ip 10.0.0.90 

# O compilar el binario
go build -o amt-poweron main.go
AMT_PASSWORD="XXXX" ./amt-poweron -ip 10.0.0.90 

# compilar para flint 2
El router GL.iNet GL-MT6000 (Flint 2) monta un procesador MediaTek Filogic 830 (ARM 64-bit) y corre OpenWrt/Linux.
La arquitectura de destino en Go es linux/arm64.
Comando de compilación cruzada

Compila desactivando CGO (para generar un binario 100% estático sin dependencias de libc/musl) y eliminando símbolos de depuración para reducir el tamaño al mínimo:

# 1. Compilar para Flint 2 (ARM64)
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o amt-poweron-flint2 main.go
```

# 2. Subir al router
```bash
cat amt-poweron-flint2 | ssh root@10.0.0.5 "cat > /usr/bin/amt-poweron && chmod +x /usr/bin/amt-poweron"
```

# 3. Ejecutar en el router
```bash
AMT_PASSWORD="xxxx" /usr/bin/amt-poweron -ip 10.0.0.90
```



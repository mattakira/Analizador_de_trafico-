CREATE DATABASE TrafficAnalysis;
USE TrafficAnalysis;

-- Tabla para estadísticas generales de paquetes
CREATE TABLE estadisticas_paquetes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tiempo_captura TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_paquetes INT NOT NULL
);

-- Tabla para estadísticas de protocolos
CREATE TABLE estadisticas_protocolos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_estadisticas_paquetes INT,
    protocolo INT NOT NULL,
    cantidad_paquetes INT NOT NULL,
    FOREIGN KEY (id_estadisticas_paquetes) REFERENCES estadisticas_paquetes(id) ON DELETE CASCADE
);

-- Tabla para tráfico por IP (origen y destino)
CREATE TABLE trafico_ip (
    id INT AUTO_INCREMENT PRIMARY KEY,
    id_estadisticas_paquetes INT,
    direccion_ip VARCHAR(45) NOT NULL, -- para soportar IPv4 e IPv6
    direccion ENUM('origen', 'destino') NOT NULL, -- para indicar si es IP de origen o destino
    total_bytes INT NOT NULL,
    FOREIGN KEY (id_estadisticas_paquetes) REFERENCES estadisticas_paquetes(id) ON DELETE CASCADE
);

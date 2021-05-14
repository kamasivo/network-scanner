CREATE DATABASE bp;

CREATE TABLE public.devices (
  "id" SERIAL PRIMARY KEY,
  "ip_address" VARCHAR (255),
  "os" VARCHAR (255),
  "name" VARCHAR (255),
  "vendor" VARCHAR (255),
  "num_of_vulns" int,
  "os_family" VARCHAR (255),
  "os_gen" VARCHAR (255),
  "open_ports" int
);

CREATE TABLE public.ports (
  "id" int PRIMARY KEY,
  "port_number" int,
  "ip_address" VARCHAR (255)
);
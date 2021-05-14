CREATE DATABASE db_name;

CREATE TABLE public.devices
(
    ip_address text COLLATE pg_catalog."default",
    os text COLLATE pg_catalog."default",
    name text COLLATE pg_catalog."default",
    vendor text COLLATE pg_catalog."default",
    num_of_vulns bigint,
    od_family text COLLATE pg_catalog."default",
    os_gen text COLLATE pg_catalog."default",
    open_ports bigint
)

CREATE TABLE public.ports
(
    ip_address "char"[],
    port_number bigint
)

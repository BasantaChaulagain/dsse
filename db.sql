/*
    Steps to run this file:
    - Go to psql console (psql postgres -U postgres)
    - Run this file (\i ../db.sql)
*/

-- Create db if it doesn't exist
CREATE DATABASE "DSSE"
    WITH 
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;

\c DSSE

CREATE TABLE public.accesscalls (
    id SERIAL,
    command text,
    date text,
    description text,
    args text,
    info text,
    user_id text,
    user_name text,
    computer_id text,
    from_id text,
    to_id text
);

CREATE TABLE public.resources (
    the_id SERIAL,
    id text,
    title text,
    path text,
    number text,
    description text,
    type text,
    computer_id text
);

CREATE TABLE public.log_records (
    record_id int NOT NULL,
    timestamp text,
    type text,
    pid int,
    ppid int,
    uid bigint,
    auid bigint,
    sysnum int,
    success boolean,
    args text,
    exit text,
    comm text,
    exe text,
    hostname text,
    saddr text,
    cwd text,
    inode text,
    fdpair text,
    extra_inodes text,
    filenames text
);

CREATE TABLE public.paths (
    inode int NOT NULL,
    name text,
    mode int,
    is_dir boolean
);
create table public.accounts (
  id bigint primary key,
  email text,
  owner_id bigint
);
create table public.legacy (id bigint primary key);

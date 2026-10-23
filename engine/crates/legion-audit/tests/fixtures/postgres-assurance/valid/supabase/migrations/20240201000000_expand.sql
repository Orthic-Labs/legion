set lock_timeout = '2s';
set search_path = public, pg_temp;
alter table customers add column display_name text;
alter table customers add constraint customers_name_chk check (display_name is not null) not valid;
create index concurrently customers_name_idx on customers (display_name);

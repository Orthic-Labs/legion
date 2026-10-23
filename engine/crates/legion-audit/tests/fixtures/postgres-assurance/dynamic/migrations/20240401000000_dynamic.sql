create extension if not exists pgcrypto;
do $body$
declare t text := 'accounts_' || to_char(now(), 'YYYY');
begin
  execute format('create table %I (id bigint)', t);
end
$body$;

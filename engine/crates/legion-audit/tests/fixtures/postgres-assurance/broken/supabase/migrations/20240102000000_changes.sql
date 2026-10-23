-- Each defect below is intentional (A10 fixture; never executed).
create index idx_accounts_email on public.accounts (email);
alter table public.accounts add column token uuid default gen_random_uuid();
alter table public.accounts add constraint accounts_owner_fk
  foreign key (owner_id) references public.owners (id);
alter table public.accounts alter column email set not null;
drop table public.legacy;
begin;
create index concurrently idx_accounts_owner on public.accounts (owner_id);
commit;
create function public.touch() returns trigger language plpgsql security definer as $$
begin return new; end
$$;
create policy open_read on public.accounts for select to anon using (true);

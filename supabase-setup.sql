-- =====================================================================
--  TEAM-KALENDER – Datenbank-Einrichtung für Supabase
--  Supabase → SQL Editor → "New query" → alles einfügen → "Run"
--
--  Prinzip:
--   * Ein gemeinsames Team-Konto (Authentication → Users) öffnet die App.
--   * Danach wählt jede Person ihr Profil (optional mit 4-stelliger PIN).
--   * Schreiben ist nur über die Funktionen unten möglich; diese prüfen
--     Profil, PIN und Rolle (Admin / Teilnehmer / Zuschauer).
-- =====================================================================

-- 0) NUR falls du eine ältere Version dieses Skripts schon ausgeführt hast,
--    die folgenden drei Zeilen einmal ohne "--" ausführen (löscht alte Daten!):
-- drop trigger if exists on_auth_user_created on auth.users;
-- drop function if exists public.handle_new_user() cascade;
-- drop table if exists public.items, public.pins, public.profiles cascade;

create extension if not exists pgcrypto with schema extensions;

-- 1) Tabellen ----------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  color      text not null default '#6366f1',
  role       text not null default 'teilnehmer' check (role in ('admin','teilnehmer','zuschauer')),
  has_pin    boolean not null default false,
  created_at timestamptz not null default now()
);

-- PINs liegen getrennt und sind für die App nicht lesbar
create table if not exists public.pins (
  profile_id   uuid primary key references public.profiles(id) on delete cascade,
  pin_hash     text not null,
  fails        int not null default 0,
  locked_until timestamptz
);

create table if not exists public.items (
  kind       text not null check (kind in ('event','todo','project','shop','log')),
  id         text not null,
  data       jsonb not null,
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (kind, id)
);

-- 2) Zugriff: Lesen nur mit Team-Zugang, Schreiben nur über Funktionen ---
alter table public.profiles enable row level security;
alter table public.pins     enable row level security;
alter table public.items    enable row level security;

drop policy if exists "profiles lesen" on public.profiles;
drop policy if exists "items lesen"    on public.items;
create policy "profiles lesen" on public.profiles for select to authenticated using (true);
create policy "items lesen"    on public.items    for select to authenticated using (true);

revoke all on public.profiles, public.pins, public.items from anon, authenticated;
grant select on public.profiles, public.items to authenticated;

-- 3) Interne Prüfung von Profil + PIN -----------------------------------
--    Rückgabe: Rolle oder 'noauth' | 'missing' | 'wrong' | 'locked'
--    Nach 5 falschen Eingaben wird das Profil für 5 Minuten gesperrt.
create or replace function public._tk_auth(p_uid uuid, p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare r text; h text; lu timestamptz;
begin
  if auth.uid() is null then return 'noauth'; end if;
  select role into r from public.profiles where id = p_uid;
  if r is null then return 'missing'; end if;
  select pin_hash, locked_until into h, lu from public.pins where profile_id = p_uid;
  if h is null then return r; end if;
  if lu is not null and lu > now() then return 'locked'; end if;
  if coalesce(p_pin,'') <> '' and extensions.crypt(p_pin, h) = h then
    update public.pins set fails = 0, locked_until = null where profile_id = p_uid;
    return r;
  end if;
  update public.pins
     set fails        = case when fails + 1 >= 5 then 0 else fails + 1 end,
         locked_until = case when fails + 1 >= 5 then now() + interval '5 minutes' else null end
   where profile_id = p_uid;
  return 'wrong';
end $$;

create or replace function public._tk_err(r text) returns jsonb
language sql immutable as $$
  select case r
    when 'noauth'  then jsonb_build_object('error','Nicht angemeldet')
    when 'missing' then jsonb_build_object('error','Profil nicht gefunden – bitte neu auswählen')
    when 'wrong'   then jsonb_build_object('error','PIN falsch')
    when 'locked'  then jsonb_build_object('error','PIN gesperrt – zu viele Fehlversuche, bitte 5 Minuten warten')
    else null end
$$;

-- 4) Öffentliche Funktionen für die App -------------------------------

-- Profil auswählen (PIN prüfen)
create or replace function public.tk_login(p_uid uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public._tk_auth(p_uid, p_pin);
  if public._tk_err(r) is not null then return public._tk_err(r); end if;
  return jsonb_build_object('ok', true, 'role', r);
end $$;

-- Termine, To-dos, Projekte, Einkauf, Protokoll speichern (Admin & Teilnehmer)
create or replace function public.tk_save(p_uid uuid, p_pin text, p_ups jsonb, p_dels jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text; x jsonb;
begin
  r := public._tk_auth(p_uid, p_pin);
  if public._tk_err(r) is not null then return public._tk_err(r); end if;
  if r not in ('admin','teilnehmer') then return jsonb_build_object('error','Keine Berechtigung'); end if;
  for x in select value from jsonb_array_elements(coalesce(p_ups,'[]'::jsonb)) loop
    insert into public.items (kind, id, data, updated_by, updated_at)
    values (x->>'kind', x->>'id', x->'data', p_uid, now())
    on conflict (kind, id) do update set data = excluded.data, updated_by = excluded.updated_by, updated_at = now();
  end loop;
  for x in select value from jsonb_array_elements(coalesce(p_dels,'[]'::jsonb)) loop
    delete from public.items where kind = x->>'kind' and id = x->>'id';
  end loop;
  return jsonb_build_object('ok', true);
end $$;

-- Erstes Profil anlegen (nur solange noch niemand existiert) → wird Admin
create or replace function public.tk_bootstrap(p_name text, p_color text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid;
begin
  if auth.uid() is null then return jsonb_build_object('error','Nicht angemeldet'); end if;
  if exists (select 1 from public.profiles) then return jsonb_build_object('error','Das Team ist bereits eingerichtet'); end if;
  if coalesce(trim(p_name),'') = '' then return jsonb_build_object('error','Bitte einen Namen eingeben'); end if;
  if coalesce(p_pin,'') <> '' and p_pin !~ '^[0-9]{4}$' then return jsonb_build_object('error','Die PIN muss aus 4 Ziffern bestehen'); end if;
  insert into public.profiles (name, color, role, has_pin)
  values (trim(p_name), coalesce(nullif(p_color,''),'#6366f1'), 'admin', coalesce(p_pin,'') <> '')
  returning id into v_id;
  if coalesce(p_pin,'') <> '' then
    insert into public.pins (profile_id, pin_hash) values (v_id, extensions.crypt(p_pin, extensions.gen_salt('bf')));
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- Person anlegen oder ändern (nur Admin)
create or replace function public.tk_person_save(p_uid uuid, p_pin text, p_person jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text; v_id uuid; v_role text; v_name text;
begin
  r := public._tk_auth(p_uid, p_pin);
  if public._tk_err(r) is not null then return public._tk_err(r); end if;
  if r <> 'admin' then return jsonb_build_object('error','Keine Berechtigung'); end if;
  v_role := coalesce(nullif(p_person->>'role',''), 'teilnehmer');
  v_name := trim(coalesce(p_person->>'name',''));
  if v_role not in ('admin','teilnehmer','zuschauer') then return jsonb_build_object('error','Ungültige Rolle'); end if;
  if v_name = '' then return jsonb_build_object('error','Bitte einen Namen eingeben'); end if;
  if nullif(p_person->>'id','') is not null then
    v_id := (p_person->>'id')::uuid;
    if v_role <> 'admin'
       and exists (select 1 from public.profiles where id = v_id and role = 'admin')
       and not exists (select 1 from public.profiles where role = 'admin' and id <> v_id) then
      return jsonb_build_object('error','Mindestens ein Admin muss bleiben');
    end if;
    update public.profiles
       set name = v_name, color = coalesce(nullif(p_person->>'color',''), color), role = v_role
     where id = v_id;
  else
    insert into public.profiles (name, color, role)
    values (v_name, coalesce(nullif(p_person->>'color',''),'#6366f1'), v_role)
    returning id into v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- Person entfernen (nur Admin, nicht sich selbst, mind. ein Admin bleibt)
create or replace function public.tk_person_delete(p_uid uuid, p_pin text, p_target uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public._tk_auth(p_uid, p_pin);
  if public._tk_err(r) is not null then return public._tk_err(r); end if;
  if r <> 'admin' then return jsonb_build_object('error','Keine Berechtigung'); end if;
  if p_target = p_uid then return jsonb_build_object('error','Du kannst dich nicht selbst entfernen'); end if;
  if exists (select 1 from public.profiles where id = p_target and role = 'admin')
     and not exists (select 1 from public.profiles where role = 'admin' and id <> p_target) then
    return jsonb_build_object('error','Mindestens ein Admin muss bleiben');
  end if;
  delete from public.profiles where id = p_target;
  return jsonb_build_object('ok', true);
end $$;

-- PIN setzen/entfernen (eigene PIN: jede Person; fremde PIN: nur Admin)
create or replace function public.tk_set_pin(p_uid uuid, p_pin text, p_target uuid, p_new text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := public._tk_auth(p_uid, p_pin);
  if public._tk_err(r) is not null then return public._tk_err(r); end if;
  if p_target <> p_uid and r <> 'admin' then return jsonb_build_object('error','Keine Berechtigung'); end if;
  if coalesce(p_new,'') = '' then
    delete from public.pins where profile_id = p_target;
    update public.profiles set has_pin = false where id = p_target;
  else
    if p_new !~ '^[0-9]{4}$' then return jsonb_build_object('error','Die PIN muss aus 4 Ziffern bestehen'); end if;
    insert into public.pins (profile_id, pin_hash) values (p_target, extensions.crypt(p_new, extensions.gen_salt('bf')))
    on conflict (profile_id) do update set pin_hash = excluded.pin_hash, fails = 0, locked_until = null;
    update public.profiles set has_pin = true where id = p_target;
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- 5) Ausführungsrechte -------------------------------------------------
revoke execute on function public._tk_auth(uuid, text) from public, anon, authenticated;
revoke execute on function public._tk_err(text)        from public, anon, authenticated;
revoke execute on function public.tk_login(uuid, text)                     from public, anon;
revoke execute on function public.tk_save(uuid, text, jsonb, jsonb)        from public, anon;
revoke execute on function public.tk_bootstrap(text, text, text)           from public, anon;
revoke execute on function public.tk_person_save(uuid, text, jsonb)        from public, anon;
revoke execute on function public.tk_person_delete(uuid, text, uuid)       from public, anon;
revoke execute on function public.tk_set_pin(uuid, text, uuid, text)       from public, anon;
grant  execute on function public.tk_login(uuid, text)                     to authenticated;
grant  execute on function public.tk_save(uuid, text, jsonb, jsonb)        to authenticated;
grant  execute on function public.tk_bootstrap(text, text, text)           to authenticated;
grant  execute on function public.tk_person_save(uuid, text, jsonb)        to authenticated;
grant  execute on function public.tk_person_delete(uuid, text, uuid)       to authenticated;
grant  execute on function public.tk_set_pin(uuid, text, uuid, text)       to authenticated;

-- 6) Live-Synchronisation ----------------------------------------------
do $$ begin
  begin alter publication supabase_realtime add table public.items;    exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.profiles; exception when duplicate_object then null; end;
end $$;

-- 7) Fotos & Dateien an Terminen (Speicher "anhaenge", max. 25 MB pro Datei) --
insert into storage.buckets (id, name, public, file_size_limit)
values ('anhaenge', 'anhaenge', false, 26214400)
on conflict (id) do update set public = false, file_size_limit = 26214400;

drop policy if exists "anhaenge lesen"     on storage.objects;
drop policy if exists "anhaenge hochladen" on storage.objects;
drop policy if exists "anhaenge loeschen"  on storage.objects;
create policy "anhaenge lesen"     on storage.objects for select to authenticated using (bucket_id = 'anhaenge');
create policy "anhaenge hochladen" on storage.objects for insert to authenticated with check (bucket_id = 'anhaenge');
create policy "anhaenge loeschen"  on storage.objects for delete to authenticated using (bucket_id = 'anhaenge');

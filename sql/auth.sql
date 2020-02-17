--CREATE USER auth with password 'auth';
CREATE SCHEMA AUTHORIZATION auth;
GRANT CONNECT ON DATABASE horizon TO auth;
GRANT USAGE ON SCHEMA auth TO auth;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER ON TABLES TO auth;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT, UPDATE ON SEQUENCES TO auth;

SET search_path TO auth;

CREATE SEQUENCE seq_auth_session START 10000000;
CREATE SEQUENCE seq_users START 20000000;

create table auth_session (
    session_id character varying(100) primary key DEFAULT nextval('seq_auth_session'),
    auth_info character varying(2048),
    char_info character varying(2048),
    error character varying(100),
    user_agent character varying(2048),
    redirect_url character varying(2048) not null,
    created timestamp not null default CURRENT_TIMESTAMP,
    updated timestamp not null default CURRENT_TIMESTAMP
);

create table character_token (
    access_token character varying(256) primary key,
    session_id character varying(100) not null references auth_session(session_id),
    token_type character varying(100) not null,
    scopes character varying(4000),
    created timestamp not null default CURRENT_TIMESTAMP,
    expires_in integer not null,
    refresh_token character varying(256) references character_token(access_token),
    character_id integer not null,
    valid numeric(1) not null default 1
);

create table users (
    user_id integer primary key DEFAULT nextval('seq_users'),
    character_id integer,
    created timestamp not null default CURRENT_TIMESTAMP
);

create table user_token (
    token character varying(100) PRIMARY KEY,
    user_id integer not null references users(user_id),
    created timestamp not null default CURRENT_TIMESTAMP,
    expires timestamp not null,
    device character varying(1000) not null,
    refresh_token character varying(100) references user_token(token),
    valid numeric(1) not null default 1
);

create table characters (
    character_id integer primary key,
    user_id integer not null references users(user_id),
    owner_hash character varying (100) not null,
    lcharacter_name character varying (100) not null,
    created timestamp not null default CURRENT_TIMESTAMP
);


create or replace function random_string(IN plength int) 
  RETURNS varchar AS $$ 
DECLARE
  alphanumeric constant varchar := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  i int;
  idx int;
  result varchar := '';
BEGIN
  FOR i IN 1.. plength LOOP
    idx := (random() * 61 + 1)::INT;
    result := result || substring(alphanumeric, idx, 1);
  END LOOP;
  RETURN result;
END;
$$ LANGUAGE plpgsql;


CREATE TYPE auth_info AS (
  access_token varchar,
  token_type varchar,
  expires_in integer,
  refresh_token varchar
);

CREATE TYPE char_info AS (
  "CharacterID" integer,
  "CharacterName" varchar,
  "Scopes" varchar,
  "CharacterOwnerHash" varchar
);


CREATE OR REPLACE FUNCTION user_sign_in(IN psession_id varchar, IN pdevice varchar, IN pauth_info varchar, IN pchar_info varchar)
  RETURNS varchar AS $$
DECLARE
  lcharacter_id integer;
  lcharacter_name varchar;
  lscopes varchar;
  lowner_hash varchar;
  lowner_hash_old varchar;
  luser_id integer;
  luser_token varchar;
  lexpires timestamp;
BEGIN
  -- Maybe, think of a better validation
  if psession_id is null or pauth_info is null or pchar_info is null or pdevice is null then
    RAISE EXCEPTION 'psession_id, pauth_info and pchar_info are required % % % %', psession_id, pauth_info, pchar_info, pdevice;
  end if;
  
  -- Parse JSON parts
  select "CharacterID", "CharacterName", "Scopes", "CharacterOwnerHash" 
  into lcharacter_id, lcharacter_name, lscopes, lowner_hash
  from json_populate_record(null::char_info, pchar_info::json);
  
  if lcharacter_id is null or lowner_hash is null then
    RAISE EXCEPTION 'Character info requires CharacterID and CharacterOwnerHash %', pchar_info;
  end if;

  -- Check if the character already exists
  select owner_hash, user_id into lowner_hash_old, luser_id
  from characters
  where character_id = lcharacter_id;
  
  if lowner_hash_old is null then
    -- This is a new character, create user record first
    insert into users (character_id) values (lcharacter_id) returning user_id into luser_id;
    -- Now finish with character
    insert into characters (character_id, user_id, owner_hash, lcharacter_name)
    values (lcharacter_id, luser_id, lowner_hash, lcharacter_name);
  else
    -- Existing character, see if the owner has changed
    if lowner_hash <> lowner_hash_old then
      -- Unlink character from the old user
      update users set character_id = null where user_id = luser_id;
      -- Create new user for this character
      insert into users (character_id) values (lcharacter_id) returning user_id into luser_id;
    end if;
  end if;

  -- at this point, we should be done with user. Just double check for dev(me) mistake
  if luser_id is null then
    RAISE EXCEPTION 'User was not created for character(sorry about that) %', pchar_info;
  end if;

  -- Update auth_session
  update auth_session
  set auth_info = pauth_info, 
    char_info = pchar_info, 
    updated = CURRENT_TIMESTAMP
  where session_id = psession_id;
    
  -- Create character_token reord
  insert into character_token (access_token, session_id, token_type, scopes, expires_in, character_id)
  select access_token, psession_id, token_type, lscopes, expires_in, lcharacter_id 
    from json_populate_record(null::auth_info, pauth_info::json);

  -- The last step - User Token
  select token, expires
  into luser_token, lexpires
  from user_token
  where user_id = luser_id 
    and device = pdevice
  order by expires desc
  limit 1;
   
  -- See if the token already exists
  if lexpires is null or lexpires <= CURRENT_TIMESTAMP then
    insert into user_token(token, user_id, device, expires, refresh_token)
    values (random_string(30), luser_id, pdevice, CURRENT_TIMESTAMP + interval '1 day', luser_token)
    returning token into luser_token;
  end if;
  return luser_token;
END;
$$ LANGUAGE plpgsql;

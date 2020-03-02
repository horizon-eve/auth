CREATE USER auth with password 'auth';
ALTER USER auth CREATEROLE;
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
    client_verify character varying(128) not null UNIQUE,
    created timestamp not null default CURRENT_TIMESTAMP,
    updated timestamp not null default CURRENT_TIMESTAMP,
    committed numeric(1) not null default 0
);

create table character_token (
    access_token character varying(256) primary key,
    character_id integer not null,
    session_id character varying(100) not null references auth_session(session_id),
    token_type character varying(100) not null,
    scopes character varying(4000),
    created timestamp not null default CURRENT_TIMESTAMP,
    expires_in integer not null,
    refresh_token character varying(256) references character_token(access_token),
    valid numeric(1) not null default 1
);

create table users (
    user_id character varying(20) primary key DEFAULT concat('u',nextval('seq_users')),
    character_id integer,
    created timestamp not null default CURRENT_TIMESTAMP
);

create table user_token (
    token character varying(100) PRIMARY KEY,
    user_id character varying(20) not null references users(user_id),
    created timestamp not null default CURRENT_TIMESTAMP,
    expires timestamp not null,
    device character varying(1000) not null,
    refresh_token character varying(100) references user_token(token),
    valid numeric(1) not null default 1
);

create table characters (
    character_id integer primary key,
    user_id character varying(20) not null references users(user_id),
    owner_hash character varying (100) not null,
    character_name character varying (100) not null,
    created timestamp not null default CURRENT_TIMESTAMP
);

-- Security Policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
DROP ROLE IF EXISTS IUSER;
CREATE ROLE IUSER;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO IUSER;
GRANT USAGE ON SCHEMA auth TO IUSER;
CREATE POLICY access_my_user ON users TO IUSER USING (user_id = current_user);
CREATE POLICY admin_users ON users TO auth USING (true) WITH CHECK (true);

-- Trigger Procedure to create a new pg user
create or replace function create_user() 
RETURNS TRIGGER AS $$
BEGIN
  EXECUTE 'CREATE ROLE ' || NEW.user_id || ';';
  EXECUTE 'GRANT IUSER TO ' || NEW.user_id || ';';
  EXECUTE 'GRANT IUSER TO ' || NEW.user_id || ';';
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- insert character token trigger
CREATE TRIGGER insert_user
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE PROCEDURE create_user();

-- Trigger Procedure to send character_token auth event
create or replace function notify_character_token() 
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('auth', '{"event": "character_token", "access_token": "' || NEW.access_token || '", "character_id": "' || NEW.character_id || '", "scopes": "' || NEW.scopes || '", "created": "' || NEW.created || '", "expires_in": "' || NEW.expires_in || '"}');
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- insert character token trigger
CREATE TRIGGER insert_character_token
    AFTER INSERT ON character_token
    FOR EACH ROW
    EXECUTE PROCEDURE notify_character_token();

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

--select * from users
--select * from auth_session
--select user_sign_in('0w4suiq0ug8rj837a2hfkk', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.106 Safari/537.36', 'chrome-windows10-other');

CREATE OR REPLACE FUNCTION user_sign_in(IN pclient_verify varchar, IN puser_agent varchar, IN pdevice varchar)
  RETURNS varchar AS $$
DECLARE
  lsession_id varchar;
  lauth_info varchar;
  lchar_info varchar;
  luser_agent varchar;
  lcharacter_id integer;
  lcharacter_name varchar;
  lscopes varchar;
  lowner_hash varchar;
  lowner_hash_old varchar;
  luser_id varchar;
  luser_token varchar;
  lexpires timestamp;
BEGIN
  -- Maybe, think of a better validation
  if pclient_verify is null or puser_agent is null or pdevice is null then
    RAISE EXCEPTION 'pclient_verify, puser_agent and pdevice are required % % %', pclient_verify, puser_agent, pdevice;
  end if;

  -- fetch and commit the session
  select session_id, auth_info, char_info, user_agent
  into lsession_id, lauth_info, lchar_info, luser_agent
  from auth_session
  where client_verify = pclient_verify and committed = 0;
  
  if lsession_id is null then
    RAISE EXCEPTION 'No authorization to verify %', pclient_verify;
  end if;
  
  update auth_session set committed = 1, updated = CURRENT_TIMESTAMP where session_id = lsession_id;

  if puser_agent <> luser_agent then
    RAISE EXCEPTION 'No authorization to verify, my friend';
  end if;
  
  -- Parse JSON parts
  select "CharacterID", "CharacterName", "Scopes", "CharacterOwnerHash" 
  into lcharacter_id, lcharacter_name, lscopes, lowner_hash
  from json_populate_record(null::char_info, lchar_info::json);
  
  if lcharacter_id is null or lowner_hash is null then
    RAISE EXCEPTION 'Character info requires CharacterID and CharacterOwnerHash %', lchar_info;
  end if;

  -- Check if the character already exists
  select owner_hash, user_id into lowner_hash_old, luser_id
  from characters
  where character_id = lcharacter_id;
  
  if lowner_hash_old is null then
    -- This is a new character, create user record first
    insert into users (character_id) values (lcharacter_id) returning user_id into luser_id;
    -- Now finish with character
    insert into characters (character_id, user_id, owner_hash, character_name)
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

  -- Create character_token reord
  insert into character_token (access_token, session_id, token_type, scopes, expires_in, character_id)
  select access_token, lsession_id, token_type, lscopes, expires_in, lcharacter_id 
    from json_populate_record(null::auth_info, lauth_info::json);

  -- The last step - User Token
  select token, expires
  into luser_token, lexpires
  from user_token
  where user_id = luser_id 
    and device = pdevice
    and valid = 1
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
-- select * from user_sign_in('9l99eq4buuuldewm31541q', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.106 Safari/537.36', 'chrome-windows10-other');


-- User Authentication
CREATE OR REPLACE FUNCTION authenticate(IN paccess_token varchar, IN pdevice varchar)
RETURNS varchar AS $$ 
DECLARE
  luser_id varchar;
BEGIN
  if paccess_token is null or pdevice is null then
    RAISE EXCEPTION 'User was unable to authenticate % %', paccess_token, pdevice;
  end if;
  -- The last step - User Token
  select user_id
  into luser_id
  from auth.user_token
  where token = paccess_token
    and device = pdevice
    and valid = 1
    and expires > CURRENT_TIMESTAMP
  order by expires desc
  limit 1;
  -- make sure user is found
  if luser_id is null then
    RAISE EXCEPTION 'User was unable to authenticate % %', paccess_token, pdevice;
  end if;
  -- Set session to the user id
  EXECUTE 'SET SESSION AUTHORIZATION ' || luser_id || ';';
  return luser_id;
END;
$$ LANGUAGE plpgsql;


-- End authentication
CREATE OR REPLACE FUNCTION end_authentication() 
RETURNS varchar AS $$ 
BEGIN
  SET SESSION AUTHORIZATION DEFAULT;
  return current_user;
END;
$$ LANGUAGE plpgsql;

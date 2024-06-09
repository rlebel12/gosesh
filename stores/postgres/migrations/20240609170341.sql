-- Create "users" table
CREATE TABLE "users" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "identifier" character varying(200) NOT NULL, PRIMARY KEY ("id"));
-- Create index "users_identifier_key" to table: "users"
CREATE UNIQUE INDEX "users_identifier_key" ON "users" ("identifier");
-- Create "sessions" table
CREATE TABLE "sessions" ("id" uuid NOT NULL DEFAULT gen_random_uuid(), "user_id" uuid NOT NULL, "idle_at" timestamptz NOT NULL, "expire_at" timestamptz NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create index "sessions_user_id_idx" to table: "sessions"
CREATE INDEX "sessions_user_id_idx" ON "sessions" ("user_id");

create table one_time_password
(
    id          varchar    not null
        constraint one_time_password_pk
            primary key,
    user_id     varchar    not null
        references users
            on update cascade on delete cascade,
    name        varchar    null,
    secret      bytea    not null,
    enc_key_id  varchar  not null,
    last_used   bigint not null,
    last_used_step bigint not null default 0,
    kind        varchar    not null check (kind in ('email', 'time')),
    is_active   boolean default false not null
);

create unique index one_time_password_user_kind_uindex
    on one_time_password (user_id, kind);

create index one_time_password_user_active_kind_index
    on one_time_password (user_id, is_active, kind);

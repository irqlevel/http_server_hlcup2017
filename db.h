#pragma once

#include "base.h"
#include "list.h"
#include "rwlock.h"
#include "memory_pool.h"
#include "jsmn.h"
#include "misc.h"

struct user_visits {
    uint32_t user_id;
    struct list_head visits;
    struct list_head list;
};

struct location_visits {
    uint32_t location_id;
    struct list_head visits;
    struct list_head list;
};

struct user {
    uint32_t id;
    char email[MAX_STRING_SIZE];
    char first_name[MAX_STRING_SIZE];
    char last_name[MAX_STRING_SIZE];
    char gender[MAX_STRING_SIZE];
    int64_t birth_date;
    uint32_t age;
    struct list_head list;
    struct list_head visits;
};

struct visit {
    uint32_t id;
    uint32_t mark;
    uint32_t location_id;
    uint32_t user_id;
    int64_t visited_at;
    struct user *user;
    struct location *location;
    struct list_head list;
    struct list_head user_list;
    struct list_head location_list;
    struct list_head user_visits_list;
    struct list_head location_visits_list;
    size_t mark_s_len;
    size_t visited_at_s_len;
    char mark_s[2];
    char visited_at_s[12];
};

struct location {
    uint32_t id;
    uint32_t distance;
    char place[MAX_STRING_SIZE];
    char country[MAX_STRING_SIZE];
    char city[MAX_STRING_SIZE];
    struct list_head list;
    struct list_head visits;
    size_t place_len;
};

#define USERS_TABLE_SIZE 1100000
#define VISITS_TABLE_SIZE 11000000
#define LOCATIONS_TABLE_SIZE 900000

#define USERS_HASH_SIZE     (USERS_TABLE_SIZE/3)
#define LOCATIONS_HASH_SIZE (LOCATIONS_TABLE_SIZE/3)
#define VISITS_HASH_SIZE    (VISITS_TABLE_SIZE/3)
#define USER_VISITS_HASH_SIZE (USERS_TABLE_SIZE/3)
#define LOCATION_VISITS_HASH_SIZE (LOCATIONS_TABLE_SIZE/3)

struct db {
    struct list_head users[USERS_HASH_SIZE];
    struct list_head locations[LOCATIONS_HASH_SIZE];
    struct list_head visits[VISITS_HASH_SIZE];

    struct list_head user_visits[USER_VISITS_HASH_SIZE];
    struct list_head location_visits[LOCATION_VISITS_HASH_SIZE];

    struct user *users_table[USERS_TABLE_SIZE];
    struct visit *visits_table[VISITS_TABLE_SIZE];
    struct location *locations_table[LOCATIONS_TABLE_SIZE];

    int64_t users_table_misses;
    int64_t visits_table_misses;
    int64_t locations_table_misses;

    int64_t users_count;
    int64_t locations_count;
    int64_t visits_count;

    struct rwlock lock;
    int64_t now;

    struct memory_pool user_pool;
    struct memory_pool location_pool;
    struct memory_pool visit_pool;
    struct memory_pool user_visits_pool;
    struct memory_pool location_visits_pool;
    struct memory_pool visit_entry_pool;
};

int db_init(struct db *db);
void db_free(struct db *db);

int db_new_user(struct db *db, struct user_data *data);
int db_new_location(struct db *db, struct location_data *data);
int db_new_visit(struct db *db, struct visit_data *data);

int db_update_user(struct db *db, uint32_t user_id, struct user_data *data);
int db_update_location(struct db *db, uint32_t location_id, struct location_data *data);
int db_update_visit(struct db *db, uint32_t visit_id, struct visit_data *data);

int db_get_user_visits(struct db *db, uint32_t user_id,
    int64_t *from_date, int64_t *to_date,
    const char *country,
    uint32_t *to_distance,
    struct sbuf *result);

int db_get_location_average(struct db *db, uint32_t location_id,
    int64_t *from_date, int64_t *to_date,
    uint32_t *from_age, uint32_t *to_age,
    const char *gender,
    struct sbuf *buf);

int db_get_user(struct db *db, uint32_t user_id, struct sbuf *buf);
int db_get_location(struct db *db, uint32_t location_id, struct sbuf *buf);
int db_get_visit(struct db *db, uint32_t location_id, struct sbuf *buf);


int db_load_data(struct db *db, const char *path);
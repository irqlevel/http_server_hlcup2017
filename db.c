#include "db.h"
#include "logger.h"
#include "misc.h"
#include "atomic.h"

static double round_mark(double x) {
    return (double)((int64_t)(100000 * x + 0.5))/100000;
}

static int is_leap(struct tm *date)
{
    if ((date->tm_year % 400) == 0)
        return 1;
    if ((date->tm_year % 100) == 0)
        return 0;
    if ((date->tm_year % 4) == 0)
        return 1;

    return 0;
}

static int get_adjusted_birth_day(struct tm *birth_date, struct tm *now)
{
    int birth_day = birth_date->tm_yday;
    int current_day = now->tm_yday;

    if (is_leap(birth_date) && !is_leap(now) && birth_day >= 60) {
        return birth_day - 1;
    }

    if (is_leap(now) && !is_leap(birth_date) && current_day >= 60) {
        return birth_day + 1;
    }

    return birth_day;
}

static int age_at(struct tm *birth_date, struct tm *now, int *result)
{
    int years;
    int birth_day;

    if (now->tm_year < birth_date->tm_year)
        return EINVAL;

    // Get the year number change since the player's birth.
    years = now->tm_year - birth_date->tm_year;

    // If the date is before the date of birth, then not that many years have elapsed.
    birth_day = get_adjusted_birth_day(birth_date, now);
    if (now->tm_yday < birth_day) {
        if (years == 0)
            return EINVAL;

        years -= 1;
    }

    *result = years;
    return 0;
}

static int db_get_age(struct db *db, int64_t birth_date_timestamp, uint32_t *result)
{
    struct tm birth_date, now_date;
    time_t timestamp;
    int r;
    int age;

    timestamp = birth_date_timestamp;
    if (!gmtime_r(&timestamp, &birth_date))
        return EINVAL;

    timestamp = db->now;
    if (!gmtime_r(&timestamp, &now_date))
        return EINVAL;

    r = age_at(&birth_date, &now_date, &age);
    if (r)
        return r;

    bug_on(age < 0);
    *result = age;
    return 0;
}

int db_init(struct db *db)
{
    size_t i;
    int r;

    rwlock_init(&db->lock);

    for (i = 0; i < ARRAY_SIZE(db->users); i++)
        list_init(&db->users[i]);

    for (i = 0; i < ARRAY_SIZE(db->locations); i++)
        list_init(&db->locations[i]);

    for (i = 0; i < ARRAY_SIZE(db->visits); i++)
        list_init(&db->visits[i]);

    for (i = 0; i < ARRAY_SIZE(db->user_visits); i++)
        list_init(&db->user_visits[i]);

    for (i = 0; i < ARRAY_SIZE(db->location_visits); i++)
        list_init(&db->location_visits[i]);

    r = memory_pool_init(&db->user_pool, sizeof(struct user), USERS_TABLE_SIZE);
    if (r)
        return r;

    r = memory_pool_init(&db->location_pool, sizeof(struct location), LOCATIONS_TABLE_SIZE);
    if (r)
        goto free_user_pool;

    r = memory_pool_init(&db->visit_pool, sizeof(struct visit), VISITS_TABLE_SIZE);
    if (r)
        goto free_location_pool;

    r = memory_pool_init(&db->user_visits_pool, sizeof(struct user_visits), USERS_TABLE_SIZE);
    if (r)
        goto free_visit_pool;

    r = memory_pool_init(&db->location_visits_pool, sizeof(struct location_visits), LOCATIONS_TABLE_SIZE);
    if (r)
        goto free_user_visits_pool;

    memset(db->users_table, 0, sizeof(db->users_table));
    memset(db->visits_table, 0, sizeof(db->users_table));
    memset(db->locations_table, 0, sizeof(db->locations_table));

    db->users_table_misses = 0;
    db->visits_table_misses = 0;
    db->locations_table_misses = 0;

    db->users_count = 0;
    db->visits_count = 0;
    db->locations_count = 0;

    db->now = 0;

    return 0;

free_user_visits_pool:
    memory_pool_deinit(&db->user_visits_pool);
free_visit_pool:
    memory_pool_deinit(&db->visit_pool);
free_location_pool:
    memory_pool_deinit(&db->location_pool);
free_user_pool:
    memory_pool_deinit(&db->user_pool);

    return r;
}

static struct user_visits *db_alloc_user_visits(struct db *db, uint32_t user_id)
{
    struct user_visits *user_visits;

    user_visits = memory_pool_alloc(&db->user_visits_pool);
    if (!user_visits)
        return NULL;

    list_init(&user_visits->list);
    list_init(&user_visits->visits);
    user_visits->user_id = user_id;

    return user_visits;
}

static struct location_visits *db_alloc_location_visits(struct db *db, uint32_t location_id)
{
    struct location_visits *location_visits;

    location_visits = memory_pool_alloc(&db->location_visits_pool);
    if (!location_visits)
        return NULL;

    list_init(&location_visits->list);
    list_init(&location_visits->visits);
    location_visits->location_id = location_id;

    return location_visits;
}

static void db_free_user_visits(struct db *db, struct user_visits *user_visits)
{
    memory_pool_free(&db->user_visits_pool, user_visits);
}

static void db_free_location_visits(struct db *db, struct location_visits *location_visits)
{
    memory_pool_free(&db->location_visits_pool, location_visits);
}

void db_free(struct db *db)
{
    struct user *user, *user_tmp;
    struct location *location, *location_tmp;
    struct visit *visit, *visit_tmp;
    struct user_visits *user_visits, *user_visits_tmp;
    struct location_visits *location_visits, *location_visits_tmp;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(db->users); i++) {
        list_for_each_entry_safe(user, user_tmp, &db->users[i], list) {
            list_del_init(&user->list);
            memory_pool_free(&db->user_pool, user);
        }
    }

    for (i = 0; i < ARRAY_SIZE(db->locations); i++) {
        list_for_each_entry_safe(location, location_tmp, &db->locations[i], list) {
            list_del_init(&location->list);
            memory_pool_free(&db->location_pool, location);
        }
    }

    for (i = 0; i < ARRAY_SIZE(db->visits); i++) {
        list_for_each_entry_safe(visit, visit_tmp, &db->visits[i], list) {
            list_del_init(&visit->list);
            memory_pool_free(&db->visit_pool, visit);
        }
    }

    for (i = 0; i < ARRAY_SIZE(db->user_visits); i++) {
        list_for_each_entry_safe(user_visits, user_visits_tmp, &db->user_visits[i], list) {
            list_del_init(&user_visits->list);
            db_free_user_visits(db, user_visits);
        }
    }

    for (i = 0; i < ARRAY_SIZE(db->location_visits); i++) {
        list_for_each_entry_safe(location_visits, location_visits_tmp, &db->location_visits[i], list) {
            list_del_init(&location_visits->list);
            db_free_location_visits(db, location_visits);
        }
    }

    memory_pool_deinit(&db->user_pool);
    memory_pool_deinit(&db->visit_pool);
    memory_pool_deinit(&db->location_pool);
    memory_pool_deinit(&db->user_visits_pool);
    memory_pool_deinit(&db->location_visits_pool);

    log_info("users_table_misses %lld\n", atomic_read(&db->users_table_misses));
    log_info("locations_table_misses %lld\n", atomic_read(&db->locations_table_misses));
    log_info("visit_table_misses %lld\n", atomic_read(&db->visits_table_misses));

    log_info("users_count %lld\n", atomic_read(&db->users_count));
    log_info("visits_count %lld\n", atomic_read(&db->visits_count));
    log_info("locations_count %lld\n", atomic_read(&db->locations_count));
}

static struct user* db_lookup_user(struct db *db, uint32_t user_id)
{
    struct user *user;
    size_t i;
    
    if (user_id < ARRAY_SIZE(db->users_table)) {
        user = db->users_table[user_id];
        if (user)
            return user;
    }

    return NULL;

    i = hash_uint32(user_id) % ARRAY_SIZE(db->users);
    list_for_each_entry(user, &db->users[i], list) {
        if (user->id == user_id) {
            atomic_inc(&db->users_table_misses);
            return user;
        }
    }

    return NULL;
}

static struct location* db_lookup_location(struct db *db, uint32_t location_id)
{
    struct location *location;
    size_t i;
    
    if (location_id < ARRAY_SIZE(db->locations_table)) {
        location = db->locations_table[location_id];
        if (location)
            return location;
    }

    return NULL;

    i = hash_uint32(location_id) % ARRAY_SIZE(db->locations);
    list_for_each_entry(location, &db->locations[i], list) {
        if (location->id == location_id) {
            atomic_inc(&db->locations_table_misses);
            return location;
        }
    }

    return NULL;
}

static struct visit* db_lookup_visit(struct db *db, uint32_t visit_id)
{
    struct visit *visit;
    size_t i;
    
    if (visit_id < ARRAY_SIZE(db->visits_table)) {
        visit = db->visits_table[visit_id];
        if (visit)
            return visit;
    }

    return NULL;

    i = hash_uint32(visit_id) % ARRAY_SIZE(db->visits);    
    list_for_each_entry(visit, &db->visits[i], list) {
        if (visit->id == visit_id) {
            atomic_inc(&db->visits_table_misses);
            return visit;
        }
    }

    return NULL;
}

static struct user_visits* db_lookup_user_visits(struct db *db, uint32_t user_id)
{
    struct user_visits *user_visits;
    size_t i = hash_uint32(user_id) % ARRAY_SIZE(db->user_visits);
    
    list_for_each_entry(user_visits, &db->user_visits[i], list) {
        if (user_visits->user_id == user_id)
            return user_visits;
    }

    return NULL;
}

static int db_insert_user_visits(struct db *db, struct user_visits *new_user_visits)
{
    struct user_visits *user_visits;
    uint32_t user_id = new_user_visits->user_id;
    size_t i = hash_uint32(user_id) % ARRAY_SIZE(db->user_visits);

    list_for_each_entry(user_visits, &db->user_visits[i], list) {
        if (user_visits->user_id == user_id)
            return EEXIST;
    }

    list_add_tail(&new_user_visits->list, &db->user_visits[i]);
    return 0;
}

static struct location_visits* db_lookup_location_visits(struct db *db, uint32_t location_id)
{
    struct location_visits *location_visits;
    size_t i = hash_uint32(location_id) % ARRAY_SIZE(db->location_visits);
    
    list_for_each_entry(location_visits, &db->location_visits[i], list) {
        if (location_visits->location_id == location_id)
            return location_visits;
    }

    return NULL;
}

static int db_insert_location_visits(struct db *db, struct location_visits *new_location_visits)
{
    struct location_visits *location_visits;
    uint32_t location_id = new_location_visits->location_id;
    size_t i = hash_uint32(location_id) % ARRAY_SIZE(db->location_visits);
    
    list_for_each_entry(location_visits, &db->location_visits[i], list) {
        if (location_visits->location_id == location_id)
            return EEXIST;
    }

    list_add_tail(&new_location_visits->list, &db->location_visits[i]);
    return 0;
}

static struct location_visits *db_get_or_create_location_visits(struct db *db, uint32_t location_id)
{
    struct location_visits *location_visits;
    int r;

    location_visits = db_lookup_location_visits(db, location_id);
    if (!location_visits) {
        location_visits = db_alloc_location_visits(db, location_id);
        if (!location_visits) {
            return NULL;
        }
        r = db_insert_location_visits(db, location_visits);
        if (r) {
            db_free_location_visits(db, location_visits);
            return NULL;
        }
    }

    return location_visits;
}

static struct user_visits *db_get_or_create_user_visits(struct db *db, uint32_t user_id)
{
    struct user_visits *user_visits;
    int r;

    user_visits = db_lookup_user_visits(db, user_id);
    if (!user_visits) {
        user_visits = db_alloc_user_visits(db, user_id);
        if (!user_visits) {
            return NULL;
        }
        r = db_insert_user_visits(db, user_visits);
        if (r) {
            db_free_user_visits(db, user_visits);
            return NULL;
        }
    }

    return user_visits;
}

static void add_user_visit_ordered(struct user *user, struct visit *visit)
{
    struct visit *curr_visit;

    list_for_each_entry(curr_visit, &user->visits, user_list) {
        if (visit->visited_at < curr_visit->visited_at) {
            list_add_tail(&visit->user_list, &curr_visit->user_list);
            return;
        }
    }

    list_add_tail(&visit->user_list, &user->visits);
}

int db_new_user(struct db *db, struct user_data *data)
{
    struct user *user;
    struct user_visits *user_visits;
    struct visit *visit;
    size_t i;
    int r;

    if (!json_uint32_is_valid(&data->id) || !json_string_is_valid(&data->email)
        || !json_string_is_valid(&data->first_name) || !json_string_is_valid(&data->last_name)
        || !json_string_is_valid(&data->gender) || !json_int64_is_valid(&data->birth_date))
    {
        return EINVAL;
    }

    if (strlen(data->gender.value) != 1 ||
        (data->gender.value[0] != 'm' && data->gender.value[0] != 'f')) {
        return EINVAL;
    }

    rwlock_lock(&db->lock);
    if (db_lookup_user(db, data->id.value)) {
        r = EEXIST;
        goto unlock;
    }

    user = memory_pool_alloc(&db->user_pool);
    if (!user) {
        r = ENOMEM;
        goto unlock;
    }

    user->id = data->id.value;
    strncpy(user->email, data->email.value, strlen(data->email.value) + 1);
    strncpy(user->first_name, data->first_name.value, strlen(data->first_name.value) + 1);
    strncpy(user->last_name, data->last_name.value, strlen(data->last_name.value) + 1);
    strncpy(user->gender, data->gender.value, strlen(data->gender.value) + 1);
    user->birth_date = data->birth_date.value;
    list_init(&user->visits);

    r = db_get_age(db, user->birth_date, &user->age);
    if (r) {
        log_error("get_age error %d\n", r);
        goto unlock_free;
    }

    user_visits = db_get_or_create_user_visits(db, user->id);
    if (!user_visits) {
        r = ENOMEM;
        goto unlock_free;
    }

    list_for_each_entry(visit, &user_visits->visits, user_visits_list) {
        if (visit->user != user) {
            bug_on(visit->user);
            bug_on(!list_empty(&visit->user_list));

            add_user_visit_ordered(user, visit);
            visit->user = user;
        }
    }

    if (user->id < ARRAY_SIZE(db->users_table))
        db->users_table[user->id] = user;

    atomic_inc(&db->users_count);

    i = hash_uint32(user->id) % ARRAY_SIZE(db->users);
    list_add_tail(&user->list, &db->users[i]);
    r = 0;

unlock:
    rwlock_unlock(&db->lock);
    return r;

unlock_free:
    rwlock_unlock(&db->lock);
    memory_pool_free(&db->user_pool, user);
    return r;
}

int db_new_location(struct db *db, struct location_data *data)
{
    struct location *location;
    struct location_visits *location_visits;
    struct visit *visit;
    size_t i;
    int r;

    if (!json_uint32_is_valid(&data->id) || !json_string_is_valid(&data->place)
        || !json_string_is_valid(&data->country) || !json_string_is_valid(&data->city)
        || !json_uint32_is_valid(&data->distance))
        return EINVAL;

    rwlock_lock(&db->lock);
    if (db_lookup_location(db, data->id.value)) {
        r = EEXIST;
        goto unlock;
    }

    location = memory_pool_alloc(&db->location_pool);
    if (!location) {
        r = ENOMEM;
        goto unlock;
    }

    location->id = data->id.value;
    location->place_len = strlen(data->place.value);
    strncpy(location->place, data->place.value, location->place_len + 1);
    strncpy(location->country, data->country.value, strlen(data->country.value) + 1);
    strncpy(location->city, data->city.value, strlen(data->city.value) + 1);
    location->distance = data->distance.value;
    list_init(&location->visits);

    location_visits = db_get_or_create_location_visits(db, location->id);
    if (!location_visits) {
        r = ENOMEM;
        goto unlock_free;
    }

    list_for_each_entry(visit, &location_visits->visits, location_visits_list) {
        if (visit->location != location) {
            bug_on(visit->location);
            list_add_tail(&visit->location_list, &location->visits);
            visit->location = location;
        }
    }

    if (location->id < ARRAY_SIZE(db->locations_table))
        db->locations_table[location->id] = location;

    atomic_inc(&db->locations_count);

    i = hash_uint32(location->id) % ARRAY_SIZE(db->locations);
    list_add_tail(&location->list, &db->locations[i]);
    r = 0;
unlock:
    rwlock_unlock(&db->lock);
    return r;

unlock_free:
    rwlock_unlock(&db->lock);
    memory_pool_free(&db->location_pool, location);
    return r;
}

void db_link_visit_location(struct db *db, struct visit *visit)
{
    if (!visit->location) {
        visit->location = db_lookup_location(db, visit->location_id);
        if (visit->location) {
            list_add_tail(&visit->location_list, &visit->location->visits);
        }
    }
}

static void db_unlink_visit_location(struct db *db, struct visit *visit)
{
    if (visit->location) {
        list_del_init(&visit->location_list);
        visit->location = NULL;
    }
}

static void db_link_visit_user(struct db *db, struct visit *visit)
{
    if (!visit->user) {
        struct user *user;

        user = db_lookup_user(db, visit->user_id);
        if (user) {
            add_user_visit_ordered(user, visit);
            visit->user = user;
        }
    }
}

static void db_unlink_visit_user(struct db *db, struct visit *visit)
{
    if (visit->user) {
        list_del_init(&visit->user_list);
        visit->user = NULL;
    }
}

int db_new_visit(struct db *db, struct visit_data *data)
{
    struct visit *visit;
    struct user_visits *user_visits;
    struct location_visits *location_visits;
    size_t i;
    int r;

    if (!json_uint32_is_valid(&data->id) || !json_uint32_is_valid(&data->location)
        || !json_uint32_is_valid(&data->user) || !json_int64_is_valid(&data->visited_at)
        || !json_uint32_is_valid(&data->mark))
        return EINVAL;

    rwlock_lock(&db->lock);
    if (db_lookup_visit(db, data->id.value)) {
        r = EEXIST;
        goto unlock;
    }

    visit = memory_pool_alloc(&db->visit_pool);
    if (!visit) {
        r = ENOMEM;
        goto unlock;
    }

    visit->id = data->id.value;
    visit->location_id = data->location.value;
    visit->user_id = data->user.value;
    visit->visited_at = data->visited_at.value;
    visit->visited_at_s_len =
        snprintf(visit->visited_at_s, sizeof(visit->visited_at_s), "%" PRId64, visit->visited_at);

    visit->mark = data->mark.value;
    visit->mark_s_len =
        snprintf(visit->mark_s, sizeof(visit->mark_s), "%" PRIu32, visit->mark);

    visit->user = NULL;
    visit->location = NULL;

    list_init(&visit->list);
    list_init(&visit->user_list);
    list_init(&visit->location_list);
    list_init(&visit->user_visits_list);
    list_init(&visit->location_visits_list);

    user_visits = db_get_or_create_user_visits(db, visit->user_id);
    if (!user_visits) {
        r = ENOMEM;
        goto unlock_free_visit;
    }

    location_visits = db_get_or_create_location_visits(db, visit->location_id);
    if (!location_visits) {
        r = ENOMEM;
        goto unlock_free_visit;
    }

    db_link_visit_user(db, visit);
    db_link_visit_location(db, visit);

    list_add_tail(&visit->user_visits_list, &user_visits->visits);
    list_add_tail(&visit->location_visits_list, &location_visits->visits);

    if (visit->id < ARRAY_SIZE(db->visits_table))
        db->visits_table[visit->id] = visit;

    atomic_inc(&db->visits_count);

    i = hash_uint32(visit->id) % ARRAY_SIZE(db->visits);
    list_add_tail(&visit->list, &db->visits[i]);
    r = 0;

unlock:
    rwlock_unlock(&db->lock);
    return r;

unlock_free_visit:
    rwlock_unlock(&db->lock);

    db_unlink_visit_location(db, visit);
    db_unlink_visit_user(db, visit);

    memory_pool_free(&db->visit_pool, visit);

    return r;
}

int db_update_user(struct db *db, uint32_t user_id, struct user_data *data)
{
    struct user *user;
    int r;

    rwlock_lock(&db->lock);

    user = db_lookup_user(db, user_id);
    if (!user) {
        r = ENOENT;
        goto unlock;
    }

    if (data->email.is_null || data->first_name.is_null || data->last_name.is_null||
        data->gender.is_null || data->birth_date.is_null) {
        r = EINVAL;
        goto unlock;
    }

    if (!json_string_is_valid(&data->email) && !json_string_is_valid(&data->first_name) &&
        !json_string_is_valid(&data->last_name) && !json_string_is_valid(&data->gender) &&
        !json_int64_is_valid(&data->birth_date)) {
            r = EINVAL;
            goto unlock;
    }

    if (json_string_is_valid(&data->gender)) {
        if (strlen(data->gender.value) != 1 ||
            (data->gender.value[0] != 'm' && data->gender.value[0] != 'f')) {
            r = EINVAL;
            goto unlock;
        }
    }

    if (json_string_is_valid(&data->email)) {
        strncpy(user->email, data->email.value, strlen(data->email.value) + 1);
    }

    if (json_string_is_valid(&data->first_name)) {
        strncpy(user->first_name, data->first_name.value, strlen(data->first_name.value) + 1);
    }

    if (json_string_is_valid(&data->last_name)) {
        strncpy(user->last_name, data->last_name.value, strlen(data->last_name.value) + 1);
    }

    if (json_int64_is_valid(&data->birth_date)) {
        if (data->birth_date.value != user->birth_date) {
            user->birth_date = data->birth_date.value;
            r = db_get_age(db, user->birth_date, &user->age);
            if (r) {
                log_error("get_age error %d\n", r);
                goto unlock;
            }
        }
    }

    if (json_string_is_valid(&data->gender)) {
        strncpy(user->gender, data->gender.value, strlen(data->gender.value) + 1);
    }

    r = 0;

unlock:
    rwlock_unlock(&db->lock);
    return r;
}

int db_update_location(struct db *db, uint32_t location_id, struct location_data *data)
{
    struct location *location;
    int r;

    rwlock_lock(&db->lock);

    location = db_lookup_location(db, location_id);
    if (!location) {
        r = ENOENT;
        goto unlock;
    }

    if (data->place.is_null || data->country.is_null || data->city.is_null||
        data->distance.is_null) {
        r = EINVAL;
        goto unlock;
    }

    if (!json_string_is_valid(&data->place) && !json_string_is_valid(&data->country) &&
        !json_string_is_valid(&data->city) && !json_uint32_is_valid(&data->distance)) {
        r = EINVAL;
        goto unlock;
    }

    if (json_string_is_valid(&data->place)) {
        location->place_len = strlen(data->place.value);
        strncpy(location->place, data->place.value, location->place_len + 1);
    }

    if (json_string_is_valid(&data->country)) {
        strncpy(location->country, data->country.value, strlen(data->country.value) + 1);
    }

    if (json_string_is_valid(&data->city)) {
        strncpy(location->city, data->city.value, strlen(data->city.value) + 1);
    }

    if (json_uint32_is_valid(&data->distance)) {
        location->distance = data->distance.value;
    }

    r = 0;

unlock:
    rwlock_unlock(&db->lock);
    return r;
}

int db_update_visit(struct db *db, uint32_t visit_id, struct visit_data *data)
{
    struct visit *visit;
    struct location_visits *location_visits;
    struct user_visits *user_visits;
    int r;

    rwlock_lock(&db->lock);
    visit = db_lookup_visit(db, visit_id);
    if (!visit) {
        r = ENOENT;
        goto unlock;
    }

    db_link_visit_location(db, visit);
    db_link_visit_user(db, visit);

    if (data->location.is_null || data->user.is_null || data->visited_at.is_null||
        data->mark.is_null) {
        r = EINVAL;
        goto unlock;
    }

    if (!json_uint32_is_valid(&data->location) && !json_uint32_is_valid(&data->user) &&
        !json_int64_is_valid(&data->visited_at) && !json_uint32_is_valid(&data->mark)) {
        r = EINVAL;
        goto unlock;
    }

    if (json_uint32_is_valid(&data->location)) {

        if (data->location.value != visit->location_id) {
            location_visits = db_get_or_create_location_visits(db, visit->location_id);
            if (location_visits) {
                list_del_init(&visit->location_visits_list);
            }

            db_unlink_visit_location(db, visit);

            visit->location_id = data->location.value;

            location_visits = db_get_or_create_location_visits(db, visit->location_id);
            if (location_visits) {
                list_add_tail(&visit->location_visits_list, &location_visits->visits);
            }

            db_link_visit_location(db, visit);

        }
    }

    if (json_uint32_is_valid(&data->user)) {

        if (data->user.value != visit->user_id) {

            user_visits = db_get_or_create_user_visits(db, visit->user_id);
            if (user_visits) {
                list_del_init(&visit->user_visits_list);
            }

            db_unlink_visit_user(db, visit);

            visit->user_id = data->user.value;

            user_visits = db_get_or_create_user_visits(db, visit->user_id);
            if (user_visits) {
                list_add_tail(&visit->user_visits_list, &user_visits->visits);
            }

            db_link_visit_user(db, visit);
        }
    }

    if (json_int64_is_valid(&data->visited_at)) {
        if (visit->user)
            list_del_init(&visit->user_list);

        visit->visited_at = data->visited_at.value;
        visit->visited_at_s_len =
            snprintf(visit->visited_at_s, sizeof(visit->visited_at_s), "%" PRId64, visit->visited_at);

        if (visit->user)
            add_user_visit_ordered(visit->user, visit);
    }

    if (json_uint32_is_valid(&data->mark)) {
        visit->mark = data->mark.value;
        visit->mark_s_len = snprintf(visit->mark_s, sizeof(visit->mark_s), "%" PRId32, visit->mark);
    }

    r = 0;

unlock:
    rwlock_unlock(&db->lock);
    return r;
}

int db_get_user_visits(struct db *db, uint32_t user_id,
    int64_t *from_date, int64_t *to_date,
    const char *country,
    uint32_t *to_distance,
    struct sbuf *buf)
{
    struct user *user;
    struct visit *visit;
    struct location *location;
    int r, nr_visits;

    rwlock_read_lock(&db->lock);

    user = db_lookup_user(db, user_id);
    if (!user) {
        r = ENOENT;
        goto unlock;
    }

    r = sbuf_append(buf, "{\"visits\":[\n", 12);
    if (r)
        goto unlock;

    nr_visits = 0;
    list_for_each_entry(visit, &user->visits, user_list) {

        if (from_date) {
            if (visit->visited_at <= *from_date) {
                continue;
            }
        }

        if (to_date) {
            if (visit->visited_at >= *to_date) {
                break;
            }
        }
    
        location = visit->location;
        if (unlikely(!location))
            continue;

        if (country) {
            if (0 != strncmp(location->country, country, strlen(location->country) + 1)) {
                continue;
            }
        }

        if (to_distance) {
            if (location->distance >= *to_distance) {
                continue;
            }
        }

        r = sbuf_append(buf, "{\"mark\":", 8);
        if (r)
            goto unlock;

        r = sbuf_append(buf, visit->mark_s, visit->mark_s_len);
        if (r)
            goto unlock;

        r = sbuf_append(buf, ",\"place\":\"", 10);
        if (r)
            goto unlock;

        r = sbuf_append(buf, location->place, location->place_len);
        if (r)
            goto unlock;

        r = sbuf_append(buf, "\",\"visited_at\":", 15);
        if (r)
            goto unlock;

        r = sbuf_append(buf, visit->visited_at_s, visit->visited_at_s_len);
        if (r)
            goto unlock;

        r = sbuf_append(buf, "},\n", 3);
        if (r)
            goto unlock;

        nr_visits++;
    }

    if (nr_visits) {
        buf->ptr[buf->pos - 1] = '\0';
        buf->ptr[buf->pos - 2] = '\n';
        buf->pos--;
    }

    r = sbuf_append(buf, "]\n}\n", 4);
    if (r)
        goto unlock;

unlock:
    rwlock_read_unlock(&db->lock);
    return r;
}

int db_get_location_average(struct db *db, uint32_t location_id,
    int64_t *from_date, int64_t *to_date,
    uint32_t *from_age, uint32_t *to_age,
    const char *gender,
    struct sbuf *buf)
{
    struct location *location;
    struct user *user;
    struct visit *visit;
    uint64_t mark_sum;
    uint64_t visits_count;
    float result = 0.0;
    int r;

    if (gender) {
        if (strlen(gender) != 1 || (gender[0] != 'm' && gender[0] != 'f')) {
            return EINVAL;
        }
    }

    rwlock_read_lock(&db->lock);
    location = db_lookup_location(db, location_id);
    if (!location) {
        r = ENOENT;
        goto unlock;
    }

    visits_count = 0;
    mark_sum = 0;
    list_for_each_entry(visit, &location->visits, location_list) {

        if (from_date) {
            if (visit->visited_at <= *from_date) {
                continue;
            }
        }

        if (to_date) {
            if (visit->visited_at >= *to_date) {
                continue;
            }
        }

        user = visit->user;
        if (unlikely(!user))
            continue;

        if (gender) {
            if (strncmp(user->gender, gender, strlen(user->gender) + 1) != 0) {
                continue;
            }
        }

        if (from_age != 0 || to_age != 0) {
            if (from_age) {
                if (user->age < *from_age) {
                    continue;
                }
            }

            if (to_age) {
                if (user->age >= *to_age) {
                    continue;
                }
            }
        }

        mark_sum += ((uint64_t)visit->mark);
        visits_count++;
    }

    if (visits_count) {
        result = (float)(round_mark((double)mark_sum/(double)visits_count));
    }

    r = sbuf_printf(buf, "{\"avg\":%.5f}\n", result);

unlock:
    rwlock_read_unlock(&db->lock);
    return r;
}

int db_get_user(struct db *db, uint32_t user_id, struct sbuf *buf)
{
    struct user *user;
    int r;

    rwlock_read_lock(&db->lock);
    user = db_lookup_user(db, user_id);
    if (!user) {
        r = ENOENT;
        goto unlock;
    }

    r = sbuf_printf(buf,
        "{\"id\":%" PRIu32 ",\"email\":\"%s\",\"first_name\":\"%s\",\"last_name\":\"%s\",\"gender\":\"%s\",\"birth_date\":%" PRId64 "}\n",
        user->id, user->email, user->first_name, user->last_name, user->gender, user->birth_date);

unlock:
    rwlock_read_unlock(&db->lock);
    return r;
}

int db_get_location(struct db *db, uint32_t location_id, struct sbuf *buf)
{
    struct location *location;
    int r;

    rwlock_read_lock(&db->lock);
    location = db_lookup_location(db, location_id);
    if (!location) {
        r = ENOENT;
        goto unlock;
    }

    r = sbuf_printf(buf,
        "{\"id\":%" PRIu32 ",\"place\":\"%s\",\"city\":\"%s\",\"country\":\"%s\",\"distance\":%" PRIu32 "}\n",
        location->id, location->place, location->city, location->country, location->distance);

unlock:
    rwlock_read_unlock(&db->lock);
    return r;    
}

int db_get_visit(struct db *db, uint32_t visit_id, struct sbuf *buf)
{
    struct visit *visit;
    int r;

    rwlock_read_lock(&db->lock);
    visit = db_lookup_visit(db, visit_id);
    if (!visit) {
        r = ENOENT;
        goto unlock;
    }

    r = sbuf_printf(buf,
        "{\"id\":%" PRIu32 ",\"location\":%" PRIu32 ",\"user\":%" PRIu32 ",\"visited_at\":%" PRId64 ",\"mark\":%" PRIu32 "}\n",
        visit->id, visit->location_id, visit->user_id, visit->visited_at, visit->mark);

unlock:
    rwlock_read_unlock(&db->lock);
    return r; 
}

static const char *get_file_path_ext(const char *file_path)
{
    const char *c = file_path;
    const char *last_dot = NULL;

    while (*c != '\0') {
        if (*c == '.') {
            last_dot = c;
        }
        c++;
    }

    if (!last_dot)
        return NULL;
    if ((last_dot + 1) == c)
        return NULL;

    return last_dot + 1;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}

	return -1;
}

static int db_load_users_json_array(struct db *db, jsmntok_t *tokens, size_t nr_tokens,
                                    const char *data, size_t size)
{
    size_t used_tokens, parsed_tokens = 0;
    struct user_data user;
    int r;

    while (parsed_tokens < nr_tokens) {
        r = parse_json_user_data(tokens + parsed_tokens, nr_tokens - parsed_tokens,
                data, size, &user, &used_tokens);
        if (r)
            return r;

        r = db_new_user(db, &user);
        if (r) {
            log_error("can't insert user\n");
            return r;
        }

        parsed_tokens += used_tokens;
    }

    return 0;
}

static int db_load_locations_json_array(struct db *db, jsmntok_t *tokens, size_t nr_tokens,
                                        const char *data, size_t size)
{
    size_t used_tokens, parsed_tokens = 0;
    struct location_data location;
    int r;

    while (parsed_tokens < nr_tokens) {
        r = parse_json_location_data(tokens + parsed_tokens, nr_tokens - parsed_tokens,
                data, size, &location, &used_tokens);
        if (r)
            return r;

        r = db_new_location(db, &location);
        if (r) {
            log_error("can't insert location\n");
            return r;
        }

        parsed_tokens += used_tokens;
    }

    return 0;
}

static int db_load_visits_json_array(struct db *db, jsmntok_t *tokens, size_t nr_tokens,
                                     const char *data, size_t size)
{
    size_t used_tokens, parsed_tokens = 0;
    struct visit_data visit;
    int r;

    while (parsed_tokens < nr_tokens) {
        r = parse_json_visit_data(tokens + parsed_tokens, nr_tokens - parsed_tokens,
                data, size, &visit, &used_tokens);
        if (r)
            return r;

        r = db_new_visit(db, &visit);
        if (r) {
            log_error("can't insert visit\n");
            return r;
        }

        parsed_tokens += used_tokens;
    }

    return 0;
}

static int db_load_json_tokens(struct db *db, jsmntok_t *tokens, size_t nr_tokens,
                            const char *data, size_t size)
{
    log_debug("loading json %lu tokens\n", nr_tokens);

    if (nr_tokens < 4 || tokens[0].type != JSMN_OBJECT ||
        tokens[1].type != JSMN_STRING || tokens[2].type != JSMN_ARRAY) {
        log_error("unexpected tokens types\n");
        return EINVAL;
    }

    if (jsoneq(data, &tokens[1], "users") == 0) {
        return db_load_users_json_array(db, &tokens[3], nr_tokens - 3, data, size);
    } else if (jsoneq(data, &tokens[1], "locations") == 0) {
        return db_load_locations_json_array(db, &tokens[3], nr_tokens - 3, data, size);
    } else if (jsoneq(data, &tokens[1], "visits") == 0) {
        return db_load_visits_json_array(db, &tokens[3], nr_tokens - 3, data, size);
    }

    log_error("unxpected root object name\n");

    return EINVAL;
}

static int db_load_json(struct db *db, void *data, size_t size)
{
	jsmn_parser p;
	jsmntok_t *tokens;
    size_t nr_tokens;
    int r;
    int attempts;

    nr_tokens = 100000;
    attempts = 0;
    for (;;) {
        if (attempts == 10) {
            r = ENOMEM;
            goto out;
        }

        tokens = malloc(nr_tokens * sizeof(jsmntok_t));
        if (!tokens) {
            return ENOMEM;
        }

        jsmn_init(&p);
        r = jsmn_parse(&p, data, size, tokens, nr_tokens);
        if (r < 0) {
            if (r == JSMN_ERROR_NOMEM) {
                free(tokens);
                nr_tokens *= 2;
                attempts++;
                continue;
            }

            log_error("failed to parse JSON: %d pos %u\n", r, p.pos);
            r = EINVAL;
            goto free_tokens;
        }

        r = db_load_json_tokens(db, tokens, r, data, size);
        break;
    }

free_tokens:
    free(tokens);
out:
    return r;
}

static int db_load_json_file(struct db *db, const char *file_path)
{
    FILE *file;
    long size;
    size_t read;
    void *data;
    int r;

    file = fopen(file_path, "rb");
    if (!file)
        return errno;

    if (fseek(file, 0L, SEEK_END) == -1) {
        r = errno;
        goto close;
    }

    size = ftell(file);
    rewind(file);
    if (size < 0) {
        r = errno;
        goto close;
    }

    log_debug("load %s\n", file_path);
    r = 0;

    data = malloc(size);
    if (!data) {
        r = ENOMEM;
        goto close;
    }

    read = fread(data, 1, size, file);
    if (read != size) {
        log_error("fread read %lu size %ld\n", read, size);

        r = EIO;
        goto free_data;
    }

    r = db_load_json(db, data, read);

free_data:
    free(data);
close:
    fclose(file);

    return r;
}

static int db_load_txt_file(struct db *db, const char *file_path)
{
    FILE *file;

    log_debug("loading txt %s\n", file_path);

    file = fopen(file_path, "r");
    if (!file)
        return errno;

    fscanf(file, "%" PRId64 "\n", &db->now);

    log_debug("now is %" PRId64 "\n", db->now);

    fclose(file);
    return 0;
}

static int db_load_file(struct db *db, const char *file_path)
{
    const char *ext;

    ext = get_file_path_ext(file_path);

    if (strncmp(ext, "json", strlen("json") + 1) == 0) {
        return db_load_json_file(db, file_path);
    } else if (strncmp(ext, "txt", strlen("txt") + 1) == 0) {
        return 0;
    }

    log_error("unknown file %s ext %s\n", file_path, ext);

    return EINVAL;
}

int db_load_data(struct db *db, const char *path)
{
    DIR *d;
    char file_path[256];
    struct dirent *dir;
    int r;

    log_info("loading db %s\n", path);

    snprintf(file_path, ARRAY_SIZE(file_path), "%s/%s", path, "options.txt");
    r = db_load_txt_file(db, file_path);
    if (r) {
        log_error("can't load options file %d\n", r);
        return r;
    }

    d = opendir(path);
    if (!d) {
        r = errno;
        log_error("can't open dir %d\n", r);
        return r;
    }

    r = 0;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_REG) {
            snprintf(file_path, ARRAY_SIZE(file_path), "%s/%s", path, dir->d_name);
            r = db_load_file(db, file_path);
            if (r) {
                break;
            }
        }
    }

    closedir(d);

    if (r)
        log_error("loading db data error %d\n", r);

    log_info("load db complete\n");

    return r;
}
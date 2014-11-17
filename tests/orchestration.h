#include <bson.h>

typedef struct orchestration orchestration_t;
typedef struct orchestration_mongod orchestration_mongod_t;
typedef struct orchestration_replica_set orchestration_replica_set_t;
typedef struct orchestration_sharded_cluster orchestration_sharded_cluster_t;

orchestration_t *
orchestration_new (const char *hostname);

void
orchestration_destroy (orchestration_t *orchestration);

char **
orchestration_servers (const orchestration_t *orchestration);
char **
orchestration_replica_sets (const orchestration_t *orchestration);
char **
orchestration_sharded_clusters (const orchestration_t *orchestration);

char *
orchestration_create_mongod (orchestration_t *orchestration,
                             const bson_t    *params);
char *
orchestration_create_mongos (orchestration_t *orchestration,
                             const bson_t    *params);
char *
orchestration_create_replica_set (orchestration_t *orchestration,
                                  const bson_t    *params);
char *
orchestration_create_sharded_cluster (orchestration_t *orchestration,
                                      const bson_t    *params);

bool
orchestration_server_start (const orchestration_t *orchestration,
                            const char            *id,
                            bson_error_t          *error);

bool
orchestration_server_stop (const orchestration_t *orchestration,
                            const char            *id,
                            bson_error_t          *error);

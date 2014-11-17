#include "orchestration.h"
#include "restclient.h"

typedef struct orchestration orchestration_t;

orchestration_t *
orchestration_new (const char *hostname);

void
orchestration_destroy (orchestration_t *orchestration);

orchestration_server_t **
orchestration_servers (const orchestration_t *orchestration);
orchestration_replica_set_t **
orchestration_replica_sets (const orchestration_t *orchestration);
orchestration_sharded_cluster_t **
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

orchestration_server_t *
orchestration_server (const orchestration_t *orchestration,
                      const char            *id);
void
orchestration_server_start (const orchestration_t *orchestration,
                            const char            *id);

orchestration_replica_set_t *
orchestration_replica_set (const orchestration_t *orchestration,
                           const char            *id);
orchestration_sharded_cluster_t *
orchestration_sharded_cluster (const orchestration_t *orchestration,
                               const char            *id);

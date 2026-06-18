/**
 * @file ml_core.c
 * @brief Vectors, rules registry, models, raw inference, inputs.
 *
 * No SGD and no I/O — safe to link into a deployed scorer alongside
 * `ml_score.c` without dragging in training code.
 */

#include "ml/ml.h"
#include <math.h>

#ifdef N00B_HAVE_VECTOR_BUILTINS
typedef float v8f32 __attribute__((vector_size(32)));
#endif

// ----------------------------------------------------------------------------
// Vectors
// ----------------------------------------------------------------------------

n00b_ml_vec_t *
n00b_ml_vec_new(uint32_t length)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    n00b_ml_vec_t *vec = n00b_alloc_with_opts(n00b_ml_vec_t,
                                              N00B_ALLOC_OPTS(allocator));
    vec->length        = length;
    vec->data          = n00b_alloc_array_with_opts(float,
                                           length,
                                           N00B_ALLOC_OPTS(allocator));
    return vec;
}

n00b_ml_vec_t *
n00b_ml_vec_copy(const n00b_ml_vec_t *src)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    if (!src) return NULL;
    n00b_ml_vec_t *dst = n00b_ml_vec_new(src->length, .allocator = allocator);
    memcpy(dst->data, src->data, src->length * sizeof(float));
    return dst;
}

// ----------------------------------------------------------------------------
// Rules registry
// ----------------------------------------------------------------------------

n00b_ml_rules_t *
n00b_ml_rules_new()
    _kargs {
        n00b_allocator_t *allocator     = nullptr;
        bool              track_matches = false;
    }
{
    n00b_ml_rules_t *rules = n00b_alloc_with_opts(n00b_ml_rules_t,
                                                  N00B_ALLOC_OPTS(allocator));
    rules->groups = n00b_list_new(n00b_ml_rule_group_t);
    n00b_dict_init(&rules->group_ids,
                   .hash          = n00b_string_hash,
                   .skip_obj_hash = true);
    rules->total_size = 0;
    rules->match_log  = nullptr;
    if (track_matches) n00b_ml_rules_track_matches(rules);
    return rules;
}

n00b_ml_rule_group_id_t
n00b_ml_define_rule_group(n00b_ml_rules_t *rules,
                          n00b_string_t   *name,
                          uint32_t         size)
{
    n00b_ml_rule_group_t g = {
        .name   = name,
        .offset = rules->total_size,
        .size   = size,
    };
    uint32_t id = (uint32_t)n00b_list_len(rules->groups);
    n00b_list_push(rules->groups, g);
    n00b_dict_put(&rules->group_ids, name, id);
    rules->total_size += size;
    return id;
}

n00b_ml_rule_group_id_t
n00b_ml_define_rule_group_cstr(n00b_ml_rules_t *rules,
                               const char      *name,
                               uint32_t         size)
{
    return n00b_ml_define_rule_group(rules,
                                     n00b_string_from_cstr(name),
                                     size);
}

bool
n00b_ml_lookup_rule_group(n00b_ml_rules_t         *rules,
                          n00b_string_t           *name,
                          n00b_ml_rule_group_id_t *out_id)
{
    bool     found;
    uint32_t id = n00b_dict_get(&rules->group_ids, name, &found);
    if (found && out_id) *out_id = id;
    return found;
}

void
n00b_ml_rules_track_matches(n00b_ml_rules_t *rules)
{
    if (rules->match_log) return;
    rules->match_log = n00b_alloc(typeof(*rules->match_log));
    n00b_dict_init(rules->match_log,
                   .hash          = n00b_hash_word,
                   .skip_obj_hash = true);
}

// Record a hit in the debug-mode match log.
static void
log_match(n00b_ml_rules_t         *rules,
          n00b_ml_rule_group_id_t  group_id,
          uint32_t                 rule_id,
          n00b_string_t           *value)
{
    if (!rules->match_log) return;
    uint64_t key = ((uint64_t)group_id << 32) | (uint64_t)rule_id;
    bool     found;
    n00b_dict_t(n00b_string_t *, uint32_t) *vd
        = n00b_dict_get(rules->match_log, key, &found);
    if (!found || vd == nullptr) {
        vd = n00b_alloc(n00b_dict_t(n00b_string_t *, uint32_t));
        n00b_dict_init(vd,
                       .hash          = n00b_string_hash,
                       .skip_obj_hash = true);
        n00b_dict_put(rules->match_log, key, vd);
    }
    uint32_t cur = n00b_dict_get(vd, value, &found);
    cur          = found ? cur + 1 : 1;
    n00b_dict_put(vd, value, cur);
}

void
n00b_ml_record_match(n00b_ml_rules_t         *rules,
                     n00b_ml_vec_t           *vec,
                     n00b_ml_rule_group_id_t  group_id,
                     n00b_string_t           *value)
    _kargs { float weight = 1.0f; }
{
    n00b_ml_rule_group_t g = n00b_list_get(rules->groups, group_id);

    uint32_t h       = (uint32_t)n00b_string_hash(value);
    uint32_t rule_id = h % g.size;

    vec->data[g.offset + rule_id] += weight;

    log_match(rules, group_id, rule_id, value);
}

void
n00b_ml_record_match_cstr(n00b_ml_rules_t         *rules,
                          n00b_ml_vec_t           *vec,
                          n00b_ml_rule_group_id_t  group_id,
                          const char              *value)
    _kargs { float weight = 1.0f; }
{
    n00b_ml_rule_group_t g = n00b_list_get(rules->groups, group_id);

    uint32_t h       = (uint32_t)n00b_hash_cstring((void *)value);
    uint32_t rule_id = h % g.size;

    vec->data[g.offset + rule_id] += weight;

    if (rules->match_log) {
        log_match(rules, group_id, rule_id,
                  n00b_string_from_cstr(value));
    }
}

// ----------------------------------------------------------------------------
// Models
// ----------------------------------------------------------------------------

n00b_ml_model_t *
n00b_ml_model_new(uint32_t length)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    n00b_ml_model_t *model = n00b_alloc_with_opts(n00b_ml_model_t,
                                                  N00B_ALLOC_OPTS(allocator));
    model->weights = *n00b_ml_vec_new(length, .allocator = allocator);
    model->bias    = 0.0f;
    return model;
}

float
n00b_ml_score(const n00b_ml_model_t *model,
              const n00b_ml_vec_t   *input_vec)
{
    float    sum = model->bias;
    uint32_t n   = model->weights.length;
    float   *w   = model->weights.data;
    float   *x   = input_vec->data;

#ifdef N00B_HAVE_VECTOR_BUILTINS
    uint32_t i    = 0;
    v8f32    vsum = {0};
    for (; i + 8 <= n; i += 8) {
        v8f32 vw = *(v8f32 *)(w + i);
        v8f32 vx = *(v8f32 *)(x + i);
        vsum += vw * vx;
    }
    for (int j = 0; j < 8; j++) sum += ((float *)&vsum)[j];
    for (; i < n; i++) sum += w[i] * x[i];
#else
    for (uint32_t i = 0; i < n; i++) {
        sum += w[i] * x[i];
    }
#endif

    return sum;
}

// ----------------------------------------------------------------------------
// Inputs
// ----------------------------------------------------------------------------

n00b_ml_input_t *
n00b_ml_input_new(n00b_ml_rules_t *rules)
    _kargs { n00b_allocator_t *allocator = nullptr; }
{
    assert(rules->total_size > 0);
    n00b_ml_input_t *input = n00b_alloc_with_opts(n00b_ml_input_t,
                                                  N00B_ALLOC_OPTS(allocator));
    input->rules   = rules;
    input->matches = n00b_ml_vec_new(rules->total_size,
                                     .allocator = allocator);
    return input;
}

void
n00b_ml_input_match(n00b_ml_input_t         *input,
                    n00b_ml_rule_group_id_t  group_id,
                    n00b_string_t           *value)
    _kargs { float weight = 1.0f; }
{
    n00b_ml_record_match(input->rules, input->matches,
                         group_id, value, .weight = weight);
}

void
n00b_ml_input_match_cstr(n00b_ml_input_t         *input,
                         n00b_ml_rule_group_id_t  group_id,
                         const char              *value)
    _kargs { float weight = 1.0f; }
{
    n00b_ml_record_match_cstr(input->rules, input->matches,
                              group_id, value, .weight = weight);
}

void
n00b_ml_input_reset(n00b_ml_input_t *input)
{
    memset(input->matches->data,
           0,
           input->matches->length * sizeof(float));
}

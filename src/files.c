/* ------------------------------------------------------------------
 * SBox - File Net Processing
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Name chunk structure
 */
struct name_chunk_t
{
    size_t len;
    struct name_chunk_t *next;
    struct name_chunk_t *prev;
};

/**
 * Name stack structure
 */
struct name_stack_t
{
    size_t path_len;
    size_t path_size;
    char *path;
    struct name_chunk_t *head;
    struct name_chunk_t *tail;
};

/**
 * Create new name stack
 */
static int name_stack_new ( struct name_stack_t *stack )
{
    stack->path_len = 0;
    stack->path_size = 256;

    if ( !( stack->path = ( char * ) malloc ( stack->path_size ) ) )
    {
        return -1;
    }

    stack->path[0] = '\0';

    stack->head = NULL;
    stack->tail = NULL;

    return 0;
}

/**
 * Push name into name stack
 */
static int name_stack_push ( struct name_stack_t *stack, const char *name )
{
    size_t name_len;
    size_t new_path_len;
    char *backup;
    struct name_chunk_t *chunk;

    name_len = strlen ( name );

    new_path_len = stack->path_len + !!stack->path[0] + name_len;

    if ( new_path_len >= stack->path_size )
    {
        stack->path_size = 2 * new_path_len;
        backup = stack->path;

        if ( !( stack->path = realloc ( stack->path, stack->path_size ) ) )
        {
            free ( backup );
            return -1;
        }
    }

    if ( stack->path[0] )
    {
        stack->path[stack->path_len++] = '/';
    }

    memcpy ( stack->path + stack->path_len, name, name_len + 1 );
    stack->path_len = new_path_len;

    if ( !( chunk = ( struct name_chunk_t * ) malloc ( sizeof ( struct name_chunk_t ) ) ) )
    {
        return -1;
    }

    chunk->len = name_len;

    chunk->next = NULL;
    chunk->prev = stack->tail;

    if ( stack->tail )
    {
        stack->tail->next = chunk;
    }

    stack->tail = chunk;

    if ( !stack->head )
    {
        stack->head = chunk;
    }

    return 0;
}

/**
 * Pop name from name stack and discard it
 */
static int name_stack_pop_discard ( struct name_stack_t *stack )
{
    struct name_chunk_t *last;

    if ( !stack->tail )
    {
        return -1;
    }

    last = stack->tail;

    if ( stack->path_len == last->len )
    {
        stack->path_len = 0;

    } else
    {
        if ( stack->path_len < 1 + last->len )
        {
            return -1;
        }

        stack->path_len -= 1 + last->len;
    }

    stack->path[stack->path_len] = '\0';

    stack->tail = last->prev;

    if ( stack->tail )
    {
        stack->tail->next = NULL;

    } else
    {
        stack->head = NULL;
    }

    free ( last );

    return 0;
}

/**
 * Free name stack from memory
 */
static void name_stack_free ( struct name_stack_t *stack )
{
    struct name_chunk_t *ptr;
    struct name_chunk_t *next;

    for ( ptr = stack->head; ptr; ptr = next )
    {
        next = ptr->next;
        free ( ptr );
    }

    free ( stack->path );
}

/**
 * Create new xcbackup node with name
 */
static struct xcbackup_node_t *xcbackup_node_new ( const char *name )
{
    size_t name_len;
    struct xcbackup_node_t *node;

    if ( !( node = ( struct xcbackup_node_t * ) calloc ( 1, sizeof ( struct xcbackup_node_t ) ) ) )
    {
        return NULL;
    }

    if ( name )
    {
        name_len = strlen ( name );

        if ( !( node->name = ( char * ) malloc ( name_len + 1 ) ) )
        {
            free ( node );
            return NULL;
        }

        memcpy ( node->name, name, name_len + 1 );
    }

    return node;
}

static int file_net_append_child ( struct xcbackup_node_t *parent, struct xcbackup_node_t *child )
{
    child->next = NULL;
    child->prev = parent->tail;

    if ( parent->tail )
    {
        parent->tail->next = child;
    }

    parent->tail = child;

    if ( !parent->head )
    {
        parent->head = child;
    }

    return 0;
}

/**
 * Create new file net from paths internal
 */
struct xcbackup_node_t *build_file_net_in ( struct name_stack_t *stack, const char *name )
{
    DIR *dir;
    struct dirent *entry;
    struct xcbackup_node_t *node;
    struct xcbackup_node_t *child;
    struct stat statbuf;

    if ( !( node = xcbackup_node_new ( name ) ) )
    {
        return NULL;
    }

    if ( name_stack_push ( stack, name ) < 0 )
    {
        free_file_net ( node );
        return NULL;
    }

    if ( stat ( stack->path, &statbuf ) < 0 )
    {
        perror ( stack->path );
        free_file_net ( node );
        return NULL;
    }

    node->mode = statbuf.st_mode;
    node->mtime = statbuf.st_mtime;

    if ( statbuf.st_mode & S_IFDIR )
    {
        if ( !( dir = opendir ( stack->path ) ) )
        {
            perror ( stack->path );
            free_file_net ( node );
            return NULL;
        }

        while ( ( entry = readdir ( dir ) ) )
        {
            if ( !strcmp ( entry->d_name, "." ) || !strcmp ( entry->d_name, ".." ) )
            {
                continue;
            }

            if ( !( child = build_file_net_in ( stack, entry->d_name ) ) )
            {
                free_file_net ( node );
                return NULL;
            }

            file_net_append_child ( node, child );
        }

        closedir ( dir );

    } else
    {
        node->size = statbuf.st_size;
    }

    if ( name_stack_pop_discard ( stack ) < 0 )
    {
        free_file_net ( node );
        return NULL;
    }

    return node;
}

/**
 * Create new file net from paths
 */
struct xcbackup_node_t *build_file_net ( const char *paths[] )
{
    struct xcbackup_node_t *root;
    struct xcbackup_node_t *child;
    struct name_stack_t stack;

    if ( !( root = xcbackup_node_new ( NULL ) ) )
    {
        return NULL;
    }

    if ( name_stack_new ( &stack ) < 0 )
    {
        free_file_net ( root );
        return NULL;
    }

    if ( !paths[0] )
    {
        free_file_net ( root );
        return NULL;
    }

    while ( paths[0] )
    {
        if ( !( child = build_file_net_in ( &stack, *paths ) ) )
        {
            free_file_net ( root );
            name_stack_free ( &stack );
            return NULL;
        }

        file_net_append_child ( root, child );

        paths++;
    }

    if ( stack.head || stack.tail )
    {
        free_file_net ( root );
        root = NULL;
    }

    name_stack_free ( &stack );

    return root;
}

/**
 * Browse file net internal
 */
static int file_net_iter_in ( struct xcbackup_node_t *node, struct name_stack_t *stack,
    void *context, file_net_iter_callback callback )
{
    struct xcbackup_node_t *ptr;

    if ( name_stack_push ( stack, node->name ) < 0 )
    {
        return -1;
    }

    if ( callback ( context, node, stack->path ) < 0 )
    {
        return -1;
    }

    for ( ptr = node->head; ptr; ptr = ptr->next )
    {
        if ( file_net_iter_in ( ptr, stack, context, callback ) < 0 )
        {
            return -1;
        }
    }

    if ( name_stack_pop_discard ( stack ) < 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Browse file net
 */
int file_net_iter ( struct xcbackup_node_t *root, void *context, file_net_iter_callback callback )
{
    struct xcbackup_node_t *ptr;
    struct name_stack_t stack;

    if ( name_stack_new ( &stack ) < 0 )
    {
        return -1;
    }

    for ( ptr = root->head; ptr; ptr = ptr->next )
    {
        if ( file_net_iter_in ( ptr, &stack, context, callback ) < 0 )
        {
            name_stack_free ( &stack );
            return -1;
        }
    }

    if ( stack.head || stack.tail )
    {
        name_stack_free ( &stack );
        return -1;
    }

    name_stack_free ( &stack );
    return 0;
}

/**
 * Free file net from memory
 */
void free_file_net ( struct xcbackup_node_t *node )
{
    struct xcbackup_node_t *ptr;
    struct xcbackup_node_t *next;

    if ( node->name )
    {
        free ( node->name );
    }

    for ( ptr = node->head; ptr; ptr = next )
    {
        next = ptr->next;
        free ( ptr );
    }

    free ( node );
}

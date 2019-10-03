#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdio.h>   /* sprintf() */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)
#define OutputByte(c, byte)	do { char ch = (byte); PUTC(c, ch); } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}lept_context;

/* return a pointer to somewhere a char can be stored */
static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

/* return a pointer to somewhere from which chars can be poped */
static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v) {

	switch(*c->json) {
	case 't':
		if (c->json[1] != 'r' || c->json[2] != 'u' || c->json[3] != 'e')
			return LEPT_PARSE_INVALID_VALUE;
		else {
			c->json += 4;
			v->type = LEPT_TRUE;
		}
		break;
	case 'f':
		if (c->json[1] != 'a' || c->json[2] != 'l' || c->json[3] != 's' || c->json[4] != 'e')
			return LEPT_PARSE_INVALID_VALUE;
		else {
			c->json += 5;
			v->type = LEPT_FALSE;
		}
		break;
	case 'n':
		if (c->json[1] != 'u' || c->json[2] != 'l' || c->json[3] != 'l')
			return LEPT_PARSE_INVALID_VALUE;
		else {
			c->json += 4;
			v->type = LEPT_NULL;
		}
		break;
	default:
		return LEPT_PARSE_INVALID_VALUE;
	}

	return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    const char* p = c->json;

    /* optional '-' */
    if (p[0] == '-')
    	++p;

    /* int part */
    if (p[0] == '0')
    	++p;
    else if (ISDIGIT1TO9(p[0]))
    {
    	while (ISDIGIT(p[0]))
    		++p;
    }
    else
    	return LEPT_PARSE_INVALID_VALUE;

    /* frac part */
   if (p[0] == '.')
    {
    	if (!ISDIGIT(p[1]))
    		return LEPT_PARSE_INVALID_VALUE;
    	p += 2;
    	while (ISDIGIT(p[0]))
    		++p;
    }

    /* exp part */
   if (p[0] == 'E' || p[0] == 'e')
    {
    	++p;

    	/* optional '-' or '+' */
    	if (p[0] == '-' || p[0] == '+')
    		++p;

    	if (ISDIGIT(p[0]))
    		do {
    			++p;
    		} while (ISDIGIT(p[0]));
    	else
    		return LEPT_PARSE_INVALID_VALUE;
    }

    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE)
    	if (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)
    		return LEPT_PARSE_NUMBER_TOO_BIG;
    v->type = LEPT_NUMBER;
    c->json = p;
    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned* u) {
	int i;
	*u = 0;

    for (i = 0; i < 4; ++i)
    {
    	char ch = p[i];
    	int digit = (ch < 58) ? ch - '0': (ch < 71)? ch - 'A' + 10: ch - 'a' + 10;

    	if (-1 < digit && digit < 16)
    	{
    		*u = *u + (digit << (3 - i) * 4);
    	}
    	else
    		return NULL;
    }

    p += 4;
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    assert(0x0 <= u && u <= 0x10ffff);

    if (0x0 <= u && u <= 0x7f)
    	OutputByte(c, u & 0xff);
    else if (0x80 <= u && u <= 0x7ff)
    {
    	OutputByte(c, 0xc0 | u >> 6 & 0x1f); /* 0x1f = 00011111 */
    	OutputByte(c, 0x80 | u & 0x3f); /* 0x3f = 00111111 */
    }
    else if (0x800 <= u && u <= 0xffff)
    {
    	OutputByte(c, 0xe0 | u >> 12 & 0xf); /* 0xe0 = 11100000 */
    	OutputByte(c, 0x80 | u >> 6 & 0x3f); /* 0x80 = 10000000 */
    	OutputByte(c, 0x80 | u & 0x3f);
    }
    else
    {
    	OutputByte(c, 0xf0 | u >> 18 & 0x7); /* 0xf0 = 11110000 */
    	OutputByte(c, 0x80 | u >> 12 & 0x3f);
    	OutputByte(c, 0x80 | u >> 6 & 0x3f);
    	OutputByte(c, 0x80 | u & 0x3f);
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_string_raw(lept_context* c, char** str, size_t* len) {
	EXPECT(c, '\"');
	const char *p = c->json;
	size_t head = c->top;
	unsigned u;
	for (;;) {
	    char ch = *p++;
		switch (ch) {
		case '\\':
			switch (*p++) {
                case '\"': PUTC(c, '\"'); break;
                case '\\': PUTC(c, '\\'); break;
                case '/': PUTC(c, '/'); break;
                case 'b': PUTC(c, '\b'); break;
                case 'f': PUTC(c, '\f'); break;
                case 'n': PUTC(c, '\n'); break;
                case 'r': PUTC(c, '\r'); break;
                case 't': PUTC(c, '\t'); break;
                case 'u':
                    if (!(p = lept_parse_hex4(p, &u)))
                        STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                    if (0xd800 <= u && u <= 0xdbff)
                        if (p[0] == '\\' && p[1] == 'u')
                        {
                            p += 2;
                            unsigned int low;
                            if ((p = lept_parse_hex4(p, &low)) && 0xdc00 <= low && low <= 0xdfff)
                                u = 0x10000 + (u - 0xd800) * 0x400 + low - 0xdc00;
                            else
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                        }
                        else
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                    lept_encode_utf8(c, u);
                    break;
                default:
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
            }
			break;
		case '\"':
            *len = c->top - head;
			*str = (char *) lept_context_pop(c, *len);
			c->json = p;
			return LEPT_PARSE_OK;
		case '\0':
			STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
		default:
			u = (unsigned int)ch;
			if (u <= 31u)
				STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
			else
				PUTC(c, ch);
		}
	}
}

static int lept_parse_string(lept_context* c, lept_value* v) {
	 int ret;
	    char* s;
	    size_t len;
	    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK)
            lept_set_string(v, s, len);


	    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v);

static int lept_parse_array(lept_context* c, lept_value* v) {
    size_t size = 0, i;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
        	break;
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        }
        else {
            ret =  LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }

    for (i = 0; i < size; i++)
    	lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    return ret;
}

 static int lept_parse_object(lept_context* c, lept_value* v) {
    size_t i, size;
    lept_member m;
    char *str;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.m = 0;
        v->u.o.size = 0;
        return LEPT_PARSE_OK;
    }
    m.k = NULL;
    size = 0;
    for (;;) {
        lept_init(&m.v);

        if (*c->json != '"')
        {
        	ret = LEPT_PARSE_MISS_KEY;
        	break;
        }
        if ((ret =lept_parse_string_raw(c, &str, &m.klen)) != LEPT_PARSE_OK)
        	break;
        memcpy(m.k = (char *) malloc(m.klen + 1), str, m.klen);
        m.k[m.klen] = '\0';
        lept_parse_whitespace(c);
        if (*c->json++ != ':')
        {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        lept_parse_whitespace(c);

        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK)
            break;
        /* note that memcpy is shadow copy! */
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL;
        /* lept_free(&m.v);  error! this will free the lept_value in stack, too*/
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        }
        else if (*c->json == '}')
        {
        	v->type = LEPT_OBJECT;
        	v->u.o.size = size;
        	v->u.o.m = (lept_member *) malloc(size * sizeof(lept_member));
        	memcpy(v->u.o.m, lept_context_pop(c, size * sizeof(lept_member)), size * sizeof(lept_member));
        	c->json++;
        	return LEPT_PARSE_OK;
        }
        else
        {
        	ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
        	break;
        }
    }
    free(m.k);

    /* if parse succeeds, lept_free will do this */
    for (i = 0; i < size; i++) {
        lept_member* mem = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(mem->k);
        lept_free(&mem->v);
    }
    v->type = LEPT_NULL;
    return ret;
}


 static int lept_parse_value(lept_context* c, lept_value* v) {
     switch (*c->json) {
         case 't':  return lept_parse_literal(c, v);
         case 'f':  return lept_parse_literal(c, v);
         case 'n':  return lept_parse_literal(c, v);
         default:   return lept_parse_number(c, v);
         case '"':  return lept_parse_string(c, v);
         case '[':  return lept_parse_array(c, v);
         case '{':  return lept_parse_object(c, v);
         case '\0': return LEPT_PARSE_EXPECT_VALUE;
     }
 }

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

static void lept_stringify_string(lept_context* c, const char* s, size_t len) {
    size_t i, length = 0;
    char *buffer = (char *) malloc(6 * len + 3);
    memset(buffer, 0, 6 * len + 3);
    length += sprintf(buffer, "\"");
    for (i = 0; i < len; ++i)
    {
        unsigned char ch = (unsigned char) s[i];
        switch (ch)
        {
            case '\"':
                length += sprintf(buffer + length, "%s", "\\\"");
                break;
            case '\\':
                length += sprintf(buffer + length, "%s", "\\\\");
                break;
            case '/':
                length += sprintf(buffer + length, "%s", "\\/");
                break;
            case '\b':
                length += sprintf(buffer + length, "%s", "\\b");
                break;
            case '\f':
                length += sprintf(buffer + length, "%s", "\\f");
                break;
            case '\n':
                length += sprintf(buffer + length, "%s", "\\n");
                break;
            case '\r':
                length += sprintf(buffer + length, "%s", "\\r");
                break;
            case '\t':
                length += sprintf(buffer + length, "%s", "\\t");
                break;
            default:
                if (ch < 0x20)
                    length += sprintf(buffer + length, "\\u%04X", ch);
                else
                    length += sprintf(buffer + length, "%c", ch);
        }
    }
    length += sprintf(buffer + length, "\"");
    memcpy(lept_context_push(c, length), buffer, length);
    free(buffer);
}

static void lept_stringify_value(lept_context* c, const lept_value* v) {
    size_t i = 0;
    switch (v->type) {

        case LEPT_NULL:   PUTS(c, "null",  4); break;
        case LEPT_FALSE:  PUTS(c, "false", 5); break;
        case LEPT_TRUE:   PUTS(c, "true",  4); break;
        case LEPT_NUMBER: c->top -= 32 - sprintf(lept_context_push(c, 32), "%.17g", v->u.n); break;
        case LEPT_STRING: lept_stringify_string(c, v->u.s.s, v->u.s.len); break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (; i < v->u.a.size; ++i) {
                if (i > 0)
                    PUTC(c, ',');
                lept_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
            PUTC(c, '{');
            for (; i < v->u.o.size; ++i)
            {
                if (i > 0)
                    PUTC(c, ',');
                lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default: assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* length) {
    lept_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

void lept_copy(lept_value* dst, const lept_value* src) {
    size_t i = 0;
    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->u.a.capacity);
            for (; i < src->u.a.size; ++i)
                lept_copy(&dst->u.a.e[i], &src->u.a.e[i]);
            dst->u.a.size = src->u.a.size;
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->u.o.capacity);
            for (; i < src->u.o.size; ++i)
            {
                size_t len = src->u.o.m[i].klen;
                dst->u.o.m[i].k = (char *) malloc(len);
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, len);
                dst->u.o.m[i].klen = len;
                lept_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            dst->u.o.size = src->u.o.size;
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src) {
    assert(dst != NULL && src != NULL && src != dst);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs) {
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value temp;
        memcpy(&temp, lhs, sizeof(lept_value));
        memcpy(lhs,   rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}

void lept_free(lept_value* v) {
    size_t i;
    assert(v != NULL);
    switch (v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (i = 0; i < v->u.a.size; i++)
                lept_free(&v->u.a.e[i]);
            free(v->u.a.e);
            break;
        case LEPT_OBJECT:
            for (i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                lept_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default: break;
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

int lept_is_equal(const lept_value* lhs, const lept_value* rhs) {
    size_t i;
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type) {
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len && 
                memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size)
                return 0;
            for (i = 0; i < lhs->u.a.size; i++)
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i]))
                    return 0;
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size)
                return 0;
            for (i = 0; i < lhs->u.o.size; ++i)
            {
                size_t r_key_index;
                const char * l_key = lhs->u.o.m[i].k;
                size_t l_key_length = lhs->u.o.m[i].klen;
                lept_value *l_val = &lhs->u.o.m[i].v;
                /* key doesn't exist */
                if ((r_key_index = lept_find_object_index(rhs, l_key, l_key_length)) ==
                LEPT_KEY_NOT_EXIST)
                    return 0;
                /* value doesn't equal */
                if (!lept_is_equal(l_val, &rhs->u.o.m[r_key_index].v))
                    return 0;
            }
            return 1;
        default:
            return 1;
    }
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

void lept_set_array(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (lept_value*)malloc(capacity * sizeof(lept_value)) : NULL;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

size_t lept_get_array_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.capacity;
}

void lept_reserve_array(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity < capacity) {
        v->u.a.capacity = capacity;
        v->u.a.e = (lept_value*)realloc(v->u.a.e, capacity * sizeof(lept_value));
    }
}

void lept_shrink_array(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (lept_value*)realloc(v->u.a.e, v->u.a.capacity * sizeof(lept_value));
    }
}

void lept_clear_array(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    lept_erase_array_element(v, 0, v->u.a.size);
}

lept_value* lept_get_array_element(lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

lept_value* lept_pushback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.size == v->u.a.capacity)
        lept_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    lept_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void lept_popback_array_element(lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY && v->u.a.size > 0);
    lept_free(&v->u.a.e[--v->u.a.size]);
}

lept_value* lept_insert_array_element(lept_value* v, size_t index) {
    size_t i;
    assert(v != NULL && v->type == LEPT_ARRAY && index <= v->u.a.size);
    if (v->u.a.capacity < v->u.a.size + 1)
        lept_reserve_array(v, 2 * v->u.a.capacity);
    for (i = v->u.a.size; i > index; --i)
        lept_move(&v->u.a.e[i], &v->u.a.e[i - 1]);
    ++v->u.a.size;
    return &v->u.a.e[index];
}

void lept_erase_array_element(lept_value* v, size_t index, size_t count) {
    if (count == 0)
        return;
    size_t dst = index, src = index + count, end = v->u.a.size;
    assert(v != NULL && v->type == LEPT_ARRAY && index + count <= end);
    for (; dst < index + count; ++dst, ++src)
    {
        if (src < end)
            lept_move(&v->u.a.e[dst], &v->u.a.e[src]);
        else
            break;
    }
    if (dst >= index + count && src < end)
        while (src < end)
        {
            lept_move(&v->u.a.e[dst], &v->u.a.e[src]);
            ++src;
            ++dst;
        }
    if (src >= end && dst < index + count)
        while (dst < index + count)
        {
            lept_free(&v->u.a.e[dst]);
            ++dst;
        }

    v->u.a.size -= count;
}

void lept_set_object(lept_value* v, size_t capacity) {
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (lept_member*)malloc(capacity * sizeof(lept_member)) : NULL;
}

size_t lept_get_object_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

size_t lept_get_object_capacity(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.capacity;
}

void lept_reserve_object(lept_value* v, size_t capacity) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity < capacity)
    {
        v->u.o.m = (lept_member *) realloc(v->u.o.m, capacity * sizeof(lept_member));
        v->u.o.capacity = capacity;
    }
}

void lept_shrink_object(lept_value* v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity > v->u.o.size)
    {
        v->u.o.m = (lept_member *) realloc(v->u.o.m, v->u.o.size * sizeof(lept_member));
        v->u.o.capacity = v->u.o.size;
    }
}

void lept_clear_object(lept_value* v) {
    size_t i, size = v->u.o.size;
    assert(v != NULL && v->type == LEPT_OBJECT);
    for (i = 0; i < size; ++i)
        lept_remove_object_value(v, 0);
}

const char* lept_get_object_key(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

size_t lept_find_object_index(const lept_value* v, const char* key, size_t klen) {
    size_t i;
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (i = 0; i < v->u.o.size; i++)
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0)
            return i;
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(lept_value* v, const char* key, size_t klen) {
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen) {
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    if (v->u.o.capacity < v->u.o.size + 1)
        lept_reserve_object(v, v->u.o.capacity == 0 ? 1: 2 * v->u.o.capacity);
    v->u.o.m[v->u.o.size].k = (char *) malloc(klen);
    memcpy(v->u.o.m[v->u.o.size].k, key, klen);
    v->u.o.m[v->u.o.size].klen = klen;
    return &v->u.o.m[v->u.o.size++].v;
}

void lept_remove_object_value(lept_value* v, size_t index) {
    size_t dst = index, end = v->u.o.size -1 ;
    assert(v != NULL && v->type == LEPT_OBJECT && index < v->u.o.size);
    if (index < end)
        while (dst < end) {
            size_t len = v->u.o.m[dst + 1].klen;
            lept_move(&v->u.o.m[dst].v, &v->u.o.m[dst + 1].v);
            v->u.o.m[dst].klen = len;
            v->u.o.m[dst].k = (char *) realloc(v->u.o.m[dst].k, len);
            memcpy(v->u.o.m[dst].k, v->u.o.m[dst + 1].k, len);
            ++dst;
        }
    lept_free(&v->u.o.m[end].v);
    free(v->u.o.m[end].k);
    v->u.o.m[end].klen = 0;

    --v->u.o.size;
}

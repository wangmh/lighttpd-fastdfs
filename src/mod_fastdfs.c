/*
 * mod_fastdfs.c
 *
 *  Created on: 2011-4-5
 *      Author: saint
 */
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <fdfs_client.h>
#include <magick/MagickCore.h>
#include "base.h"
#include <logger.h>
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#include "stat_cache.h"
#include "etag.h"
#include "response.h"
#include "status_counter.h"

#include "version.h"

#ifdef LIGHTTPD_V14
#include "splaytree.h"
#endif

#define FADTDFS_PROF

#define CONFIG_FASTDFS_CLIENT_CONF "fastdfs.conf"
#define CONFIG_FASTDFS_COVERT_IMG_TYPES "fastdfs.covert-filetypes"
#define CONFIG_FASTDFS_COVERT_IMG_SIZE "fastdfs.covert-filesize"
#define CONFIG_FASTDFS_COVERT_IMG_ENABLE "fastdfs.covert-enable"

#ifdef FADTDFS_PROF
long timer(int reset)
{
	static long start = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	/* return timediff */
	if (!reset)
	{
		long stop = ((long) tv.tv_sec) * 1000000 + tv.tv_usec ;
		return (stop - start);
	}

	/* reset timer */
	start = ((long) tv.tv_sec) *1000000  + tv.tv_usec  ;

	return 0;
}
#endif

typedef enum
{
	IMAGE_PREFIX, IMAGE_HIGHT, IMAGE_WIDTH, IMAGE_EXT, IMAGE_ERR
} image_info_type;

typedef struct
{
	unsigned short enable;
	array *filetypes;
	buffer *fdfs_conf;
	array *filesizes;
} plugin_config;

typedef struct
{
	PLUGIN_DATA;
	buffer *range_buf;
	plugin_config **config_storage;
	plugin_config conf;

} plugin_data;

INIT_FUNC(mod_fastdfs_init)
{
	plugin_data *p;
	p = calloc(1, sizeof(*p));
	p->range_buf = buffer_init();
	MagickCoreGenesis(NULL, MagickTrue);
	return p;
}

FREE_FUNC(mod_fastdfs_free)
{
	plugin_data *p = p_d;
	UNUSED(srv);
	if (!p)
		return HANDLER_GO_ON;
	if (p->config_storage)
	{
		size_t i;
		for (i = 0; i < srv->config_context->used; i++)
		{
			plugin_config *s = p->config_storage[i];
			array_free(s->filesizes);
			array_free(s->filetypes);
			buffer_free(s->fdfs_conf);
			free(s);
		}
		free(p->config_storage);
	}
	buffer_free(p->range_buf);
	MagickCoreTerminus();
	tracker_close_all_connections();
	fdfs_client_destroy();

	free(p);
	return HANDLER_GO_ON;
}

SETDEFAULTS_FUNC(mod_fastdfs_set_defaults)
{
	plugin_data *p = p_d;
	size_t i = 0;
	config_values_t cv[] =
	{
			{ CONFIG_FASTDFS_CLIENT_CONF, NULL, T_CONFIG_STRING,
					T_CONFIG_SCOPE_SERVER },
			{ CONFIG_FASTDFS_COVERT_IMG_ENABLE, NULL, T_CONFIG_BOOLEAN,
					T_CONFIG_SCOPE_CONNECTION },
			{ CONFIG_FASTDFS_COVERT_IMG_TYPES, NULL, T_CONFIG_ARRAY,
					T_CONFIG_SCOPE_CONNECTION },
			{ CONFIG_FASTDFS_COVERT_IMG_SIZE, NULL, T_CONFIG_ARRAY,
					T_CONFIG_SCOPE_CONNECTION },
			{ NULL, NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET } };
	if (!p)
		return HANDLER_ERROR;
	p->config_storage = calloc(1, srv->config_context->used
			* sizeof(specific_config *));
	for (i = 0; i < srv->config_context->used; i++)
	{
		plugin_config *s;
		s = calloc(1, sizeof(plugin_config));
		s->enable = 1;
		s->filesizes = array_init();
		s->filetypes = array_init();
		s->fdfs_conf = buffer_init();
		cv[0].destination = s->fdfs_conf;
		cv[1].destination = &(s->enable);
		cv[2].destination = s->filetypes;
		cv[3].destination = s->filesizes;
		p->config_storage[i] = s;
		if (0 != config_insert_values_global(srv,
				((data_config *) srv->config_context->data[i])->value, cv))
		{
			return HANDLER_ERROR;
		}
	}
	p->conf.fdfs_conf = p->config_storage[0]->fdfs_conf;
	if (buffer_is_empty(p->conf.fdfs_conf))
	{
		log_error_write(srv, __FILE__, __LINE__, "s",
				"fastdfs.conf has to be set");
		return HANDLER_ERROR;
	}
	log_init();
	g_log_context.log_level = LOG_ERR;
	int result = -1;
	if ((result = fdfs_client_init(p->conf.fdfs_conf->ptr)) != 0)
	{
		log_error_write(srv, __FILE__, __LINE__, "s",
				"fasfs file config  error: ");
		return HANDLER_ERROR;
	}

	return HANDLER_GO_ON;
}

#define PATCH_OPTION(x) \
	p->conf.x = s->x;
static int mod_fastdfs_patch_connection(server *srv, connection *con,
		plugin_data *p)
{
	size_t i, j;
	plugin_config *s = p->config_storage[0];
	PATCH_OPTION(filesizes);
	PATCH_OPTION(enable);
	PATCH_OPTION(filetypes);
	PATCH_OPTION(fdfs_conf);
	for (i = 1; i < srv->config_context->used; i++)
	{
		data_config *dc = (data_config *) srv->config_context->data[i];
		s = p->config_storage[i];
		if (!config_check_cond(srv, con, dc))
			continue;

		for (j = 0; j < dc->value->used; j++)
		{
			data_unset *du = dc->value->data[j];
			if (buffer_is_equal_string(du->key,
					CONST_STR_LEN(CONFIG_FASTDFS_COVERT_IMG_ENABLE)))
			{
				PATCH_OPTION(enable);
			}
			else if (buffer_is_equal_string(du->key,
					CONST_STR_LEN(CONFIG_FASTDFS_COVERT_IMG_SIZE)))
			{
				PATCH_OPTION(filesizes);
			}
			else if (buffer_is_equal_string(du->key,
					CONST_STR_LEN(CONFIG_FASTDFS_COVERT_IMG_TYPES)))
			{
				PATCH_OPTION(filetypes);
			}
		}
	}
	return 0;
}
#undef PATCH_OPTION

PHYSICALPATH_FUNC(mod_fastdfs_physical_handler)
{
	plugin_data *p = p_d;
	if (con->http_status != 0)
		return HANDLER_GO_ON;
	if (con->uri.path->used == 0)
	{
		return HANDLER_GO_ON;
	}
	if (con->physical.path->used == 0)
	{
		return HANDLER_GO_ON;
	}
	if (con->mode != DIRECT)
	{
		return HANDLER_GO_ON;
	}
	if (con->file_finished)
		return HANDLER_GO_ON;
	mod_fastdfs_patch_connection(srv, con, p);
	con->mode = p->id;
	return HANDLER_GO_ON;
}

static char *get_file_id(buffer *uri)
{
	char *file_id = NULL;
	if (uri->used && uri->ptr[0] == '/')
	{
		file_id = uri->ptr + 1;
	}
	else if (uri->used)
	{
		file_id = uri->ptr;
	}
	return file_id;
}

static size_t magic_resize(const char *mem, int length, buffer *buf,
		buffer *hw, buffer *file_ext)
{
	if (NULL == mem || NULL == buf || NULL == hw || NULL == file_ext)
		return -1;
	ExceptionInfo *exception;
	Image *image, *images, *images1, *resize_image, *thumbnails;
	buffer *gif = buffer_init_string(".gif");
	int is_gif = 0;
	int width, height;
	char *p;
	if (hw->used == 0)
		return -1;
	p = hw->ptr + 1;
	char *q = strchr(p, '_');
	*q = '\0';
	height = atoi(p);
	p = q + 1;
	width = atoi(p);
	*q = '_';
	if (height <= 0 || width <= 0)
		return -1;
	if (file_ext->used == 0)
	{
		return -1;
	}
	else
	{
		if (buffer_is_equal_right_len(file_ext, gif, gif->used - 1))
			is_gif = 1;
	}
	size_t len;
	//reset_image_info(image_convert_info);
	ImageInfo *image_info = CloneImageInfo((ImageInfo *) NULL);
	exception = AcquireExceptionInfo();

	images = BlobToImage(image_info, mem, length, exception);
	if (exception->severity != UndefinedException)
		CatchException(exception);
	if (images == (Image *) NULL)
		return -1;

	if (is_gif)
	{
		images1 = CoalesceImages(images, exception);
		DestroyImage(images);
		images = images1;
	}
	thumbnails = NewImageList();
	while ((image = RemoveFirstImageFromList(&images)) != (Image *) NULL)
	{
		resize_image = ResizeImage(image, height, width, LanczosFilter, 1.0,
				exception);
		if (resize_image == (Image *) NULL)
			MagickError(exception->severity, exception->reason,
					exception->description);
		(void) AppendImageToList(&thumbnails, resize_image);
		DestroyImage(image);
	}
	if (is_gif)
	{
		images1 = OptimizeImageLayers(thumbnails, exception);
		DestroyImage(thumbnails);
		thumbnails = images1;
	}

	unsigned char *dstmem = ImagesToBlob(image_info, thumbnails, &len,
			exception);
	if (dstmem == NULL)
	{
		thumbnails = DestroyImageList(thumbnails);
		image_info = DestroyImageInfo(image_info);
		exception = DestroyExceptionInfo(exception);
		return -1;
	}
	buffer_prepare_copy(buf, len);
	memcpy(buf->ptr, dstmem, len);
	buf->used = len;
	RelinquishMagickMemory(dstmem);
	thumbnails = DestroyImageList(thumbnails);
	image_info = DestroyImageInfo(image_info);
	exception = DestroyExceptionInfo(exception);
	buffer_free(gif);
	return len;
}

static int http_response_parse_range(server *srv, connection *con,
		plugin_data *p, buffer *content)
{
	int multipart = 0;
	int error;
	off_t start, end;
	const char *s, *minus;
	char *boundary = "fkj49sn38dcn3";
	data_string *ds;

	buffer *content_type = NULL;

	start = 0;
	end = content->used - 1;

	con->response.content_length = 0;

	if (NULL != (ds = (data_string *) array_get_element(con->response.headers,
			"Content-Type")))
	{
		content_type = ds->value;
	}

	for (s = con->request.http_range, error = 0; !error && *s && NULL != (minus
			= strchr(s, '-'));)
	{
		char *err;
		off_t la, le;

		if (s == minus)
		{
			/* -<stop> */

			le = strtoll(s, &err, 10);

			if (le == 0)
			{
				/* RFC 2616 - 14.35.1 */

				con->http_status = 416;
				error = 1;
			}
			else if (*err == '\0')
			{
				/* end */
				s = err;

				end = content->used - 1;
				start = content->used + le;
			}
			else if (*err == ',')
			{
				multipart = 1;
				s = err + 1;

				end = content->used - 1;
				start = content->used + le;
			}
			else
			{
				error = 1;
			}

		}
		else if (*(minus + 1) == '\0' || *(minus + 1) == ',')
		{
			/* <start>- */

			la = strtoll(s, &err, 10);

			if (err == minus)
			{
				/* ok */

				if (*(err + 1) == '\0')
				{
					s = err + 1;

					end = content->used - 1;
					start = la;

				}
				else if (*(err + 1) == ',')
				{
					multipart = 1;
					s = err + 2;

					end = content->used - 1;
					start = la;
				}
				else
				{
					error = 1;
				}
			}
			else
			{
				/* error */
				error = 1;
			}
		}
		else
		{
			/* <start>-<stop> */

			la = strtoll(s, &err, 10);

			if (err == minus)
			{
				le = strtoll(minus + 1, &err, 10);

				/* RFC 2616 - 14.35.1 */
				if (la > le)
				{
					error = 1;
				}

				if (*err == '\0')
				{
					/* ok, end*/
					s = err;

					end = le;
					start = la;
				}
				else if (*err == ',')
				{
					multipart = 1;
					s = err + 1;

					end = le;
					start = la;
				}
				else
				{
					/* error */

					error = 1;
				}
			}
			else
			{
				/* error */

				error = 1;
			}
		}

		if (!error)
		{
			if (start < 0)
				start = 0;

			/* RFC 2616 - 14.35.1 */
			if (end > content->used - 1)
				end = content->used - 1;

			if (start > content->used - 1)
			{
				error = 1;

				con->http_status = 416;
			}
		}

		if (!error)
		{
			if (multipart)
			{
				/* write boundary-header */
				buffer *b;

				b = chunkqueue_get_append_buffer(con->write_queue);

				buffer_copy_string_len(b, CONST_STR_LEN("\r\n--"));
				buffer_append_string(b, boundary);

				/* write Content-Range */
				buffer_append_string_len(b,
						CONST_STR_LEN("\r\nContent-Range: bytes "));
				buffer_append_off_t(b, start);
				buffer_append_string_len(b, CONST_STR_LEN("-"));
				buffer_append_off_t(b, end);
				buffer_append_string_len(b, CONST_STR_LEN("/"));
				buffer_append_off_t(b, content->used);

				buffer_append_string_len(b, CONST_STR_LEN("\r\nContent-Type: "));
				buffer_append_string_buffer(b, content_type);

				/* write END-OF-HEADER */
				buffer_append_string_len(b, CONST_STR_LEN("\r\n\r\n"));

				con->response.content_length += b->used - 1;

			}

			chunkqueue_append_mem(con->write_queue, content->ptr + start, end
					- start + 1);
			con->response.content_length += end - start + 1;
		}
	}

	/* something went wrong */
	if (error)
		return -1;

	if (multipart)
	{
		/* add boundary end */
		buffer *b;

		b = chunkqueue_get_append_buffer(con->write_queue);

		buffer_copy_string_len(b, "\r\n--", 4);
		buffer_append_string(b, boundary);
		buffer_append_string_len(b, "--\r\n", 4);

		con->response.content_length += b->used - 1;

		/* set header-fields */

		buffer_copy_string_len(p->range_buf,
				CONST_STR_LEN("multipart/byteranges; boundary="));
		buffer_append_string(p->range_buf, boundary);

		/* overwrite content-type */
		response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"),
				CONST_BUF_LEN(p->range_buf)) ;
	}
	else
	{
		/* add Content-Range-header */

		buffer_copy_string_len(p->range_buf, CONST_STR_LEN("bytes "));
		buffer_append_off_t(p->range_buf, start);
		buffer_append_string_len(p->range_buf, CONST_STR_LEN("-"));
		buffer_append_off_t(p->range_buf, end);
		buffer_append_string_len(p->range_buf, CONST_STR_LEN("/"));
		buffer_append_off_t(p->range_buf, content->used);

		response_header_insert(srv, con, CONST_STR_LEN("Content-Range"),
				CONST_BUF_LEN(p->range_buf)) ;
	}

	/* ok, the file is set-up */
	return 0;
}

static int is_numeric(char *str, int len)
{
	if (!str)
		return 0;
	int i;
	char c;
	for (i = 0; i < len; i++)
	{
		c = *(str + i);
		if (!isdigit(c))
			return 0;
	}
	return 1;
}

#define EXITFUNC 		buffer_reset(con->physical.path);\
						buffer_free(orgial_path);\
						buffer_free(file_hw);\
						con->mode = DIRECT;\
						buffer_free(img_content);\
						buffer_free(file_ext);\
						return HANDLER_FINISHED\


SUBREQUEST_FUNC(mod_fastdfs_subrequest)
{
	plugin_data *p = p_d;

	data_string *ds;
	data_string *filesize;
	char resize_file_id[512];
	buffer *orgial_path = NULL;
	buffer *img_content = NULL;
	buffer *file_hw = NULL;
	buffer *mtime = NULL;
	char *file_id;
	if (con->http_status != 0)
		return HANDLER_GO_ON;
	if (con->uri.path->used == 0)
		return HANDLER_GO_ON;
	if (con->physical.path->used == 0)
		return HANDLER_GO_ON;
	if (con->mode != DIRECT && con->mode != p->id)
		return HANDLER_GO_ON;
	if (con->file_finished)
		return HANDLER_GO_ON;
	switch (con->request.http_method)
	{
	case HTTP_METHOD_GET:
		break;
	default:
		return HANDLER_GO_ON;
	}
	mod_fastdfs_patch_connection(srv, con, p);
	int is_covert = 0;
	size_t k, j;
	char *ext = NULL;
	orgial_path = buffer_init();
	file_hw = buffer_init();
	img_content = buffer_init();
	buffer *file_ext = buffer_init();
	char *slash0 = NULL;
	char height[20];
	char width[20];
	char *slash1 = NULL;
	int is_break = 0;
	for (k = 0; k < p->conf.filesizes->used; k++)
	{
		filesize = (data_string *) p->conf.filesizes->data[k];
		if (filesize->value->used == 0)
			continue;
		if (strcasecmp(filesize->value->ptr, "*") == 0)//如何任何的尺寸都可以
		{
			for (j = 0; j < p->conf.filetypes->used; j++)
			{
				ds = (data_string *) p->conf.filetypes->data[j];
				if (ds->value->used == 0)
					continue;
				if (buffer_is_equal_right_len(con->physical.rel_path,
						ds->value, ds->value->used - 1))
				{//获取文件的扩展名
					ext = ds->value->ptr + 1;
					buffer *path = con->physical.rel_path;

					if ((slash0 = strrchr(path->ptr, '_')) != NULL)
					{
						*(path->ptr + path->used - ds->value->used) = '\0';
						memset(width, 0, sizeof(width));
						snprintf(width, sizeof(width), "%s", slash0 + 1);
						if (0 == is_numeric(width, strlen(width)))
						{
							is_covert = 0;
							is_break = 1;
							*(path->ptr + path->used - ds->value->used) = '.';
							break;
						}

						*(path->ptr + path->used - ds->value->used) = '.';
						*slash0 = '\0';
						if ((slash1 = strrchr(path->ptr, '_')) != NULL)
						{//如果含有第二个

							memset(height, 0, sizeof(height));
							snprintf(height, sizeof(height), "%s", slash1 + 1);
							if (0 == is_numeric(height, strlen(height)))
							{
								is_covert = 0;
								is_break = 1;
								*slash0 = '_';
								break;
							}
							*slash0 = '_';//且是整数；
							is_covert = 1;
							buffer_copy_string(file_ext, slash1);
							*slash1 = '\0';
							buffer_copy_string(orgial_path, path->ptr);
							buffer_append_string_buffer(orgial_path, ds->value);
							*slash1 = '_';
							*(path->ptr + path->used - ds->value->used) = '\0';
							buffer_copy_string(file_hw, slash1);
							*(path->ptr + path->used - ds->value->used) = '.';
							break;
						}
						else
						{
							is_covert = 0;
							is_break = 1;
							*slash0 = '_';
							break;
						}

					}
					else
					{
						is_covert = 0;
						is_break = 1;
						break;
					}

				}
			}
		}
		else
		{
			for (j = 0; j < p->conf.filetypes->used; j++)
			{
				ds = (data_string *) p->conf.filetypes->data[j];
				if (ds->value->used == 0)
					continue;

				buffer_copy_string_buffer(file_ext, filesize->value);
				buffer_append_string_buffer(file_ext, ds->value);
				if (buffer_is_equal_right_len(con->physical.rel_path, file_ext,
						file_ext->used - 1))
				{
					ext = ds->value->ptr + 1;
					buffer_copy_string_len(orgial_path,
							con->physical.rel_path->ptr,
							con->physical.rel_path->used - file_ext->used);
					buffer_append_string_buffer(orgial_path, ds->value);
					is_covert = 1;
					break;
				}
			}
		}
		if (is_covert == 1 || is_break == 1)
			break;
	}

	if (is_covert && p->conf.enable)
	{
		if (file_hw->used == 0)
			buffer_copy_string_buffer(file_hw,
					((data_string *) p->conf.filesizes->data[k])->value);
	}
#ifdef FADTDFS_PROF
	long t = 0;
	timer(1);
#endif
	TrackerServerInfo *pTrackerServer = tracker_get_connection();
	if (pTrackerServer == NULL)
	{
		log_error_write(srv, __FILE__, __LINE__,"s", "fdsf connection err");
		con->http_status = 500;
		EXITFUNC
		;
	}
#ifdef FADTDFS_PROF
	t = timer(0);
	log_error_write(srv, __FILE__, __LINE__, "sd","tracker_get_connection cost time is", t);
#endif
	file_id = get_file_id(con->physical.rel_path);
	char *new_file_id = get_file_id(orgial_path);
	FDFSFileInfo file_info;
	char *file_buf = NULL;
	int64_t file_size;
	int result;
#ifdef FADTDFS_PROF
	timer(1);
#endif
	if ((result = fdfs_get_file_info1(file_id, &file_info)) != 0)
	{
#ifdef FADTDFS_PROF
		t = timer(0);
		log_error_write(srv, __FILE__, __LINE__, "so",
				"fdfs_get_file_info1  not exist  cost time is", t);
#endif
		if (result == ENOENT)
		{//如果该文件不存在,如果是需要resize的文件，则获取源文件进行resize；
			if (is_covert && p->conf.enable)
			{//如果需要转化，获取原始文件
				if (0 != (result = storage_download_file1(pTrackerServer, NULL,
						new_file_id, &file_buf, &file_size)))
				{
					if (result == ENOENT)
					{
						con->http_status = 404;
					}
					else
					{
						con->http_status = 500;
						log_error_write(srv, __FILE__, __LINE__, "ss:o",
								"get file info error ", new_file_id, result);
					}

					EXITFUNC
					;
				}
				if ((result = magic_resize(file_buf, file_size, img_content,
						file_hw, file_ext)) > 0)
				{
					if (ext)
					{
						storage_upload_slave_by_filebuff1(pTrackerServer, NULL,
								img_content->ptr, img_content->used,
								new_file_id, file_hw->ptr, ext, NULL, 0,
								resize_file_id);
						if ((result = fdfs_get_file_info1(file_id, &file_info))
								!= 0)
						{
							if (result == ENOENT)
							{
								con->http_status = 404;
							}
							else
							{

								con->http_status = 500;
								log_error_write(srv, __FILE__, __LINE__, "ss:o",
															"get file info error ", file_id, result);
							}

							free(file_buf);
							EXITFUNC
							;
						}
					}
				}
				else
				{
					log_error_write(srv, __FILE__, __LINE__, "s",
							"resize error");
					con->http_status = 500;
					free(file_buf);
					EXITFUNC
					;
				}

			}
			else
			{
				con->http_status = 404;
				EXITFUNC
				;
			}
		}
		else
		{
			log_error_write(srv, __FILE__, __LINE__, "s", "get_file_info error");
			con->http_status = 500;
			EXITFUNC
			;
		}

	}
	else
	{
#ifdef FADTDFS_PROF
		t = timer(0);
		log_error_write(srv, __FILE__, __LINE__, "so",
				"fdfs_get_file_info1 cost time is", t);
		timer(1);
#endif

		if (0 != (result = storage_download_file1(pTrackerServer, NULL,
				file_id, &file_buf, &file_size)))
		{
#ifdef FADTDFS_PROF
			t = timer(0);
			log_error_write(srv, __FILE__, __LINE__, "so",
					"storage_download_file1 not exist  cost time is", t);
#endif
			if (result == ENOENT)
			{
				con->http_status = 404;
			}
			else
			{
				con->http_status = 500;
			}
			log_error_write(srv, __FILE__, __LINE__, "sss",
					"storage_download_file1 ", file_id, "error");
			EXITFUNC
			;
		}
#ifdef FADTDFS_PROF
		t = timer(0);
		log_error_write(srv, __FILE__, __LINE__, "so",
				"storage_download_file1 cost time is", t);
#endif
		buffer_copy_memory(img_content, file_buf, file_size + 1);
		free(file_buf);
	}
	buffer_append_string(img_content, "\0");

	buffer *content_type;
	content_type = buffer_init();
	for (k = 0; k < con->conf.mimetypes->used; k++)
	{
		ds = (data_string *) con->conf.mimetypes->data[k];
		buffer *type = ds->key;

		if (type->used == 0)
			continue;

		/* check if the right side is the same */
		if (type->used > con->physical.path->used)
			continue;

		if (0 == strncasecmp(con->physical.path->ptr + con->physical.path->used
				- type->used, type->ptr, type->used - 1))
		{
			buffer_copy_string_buffer(content_type, ds->value);
			break;
		}
	}

	if (NULL == array_get_element(con->response.headers, "Content-Type"))
	{
		if (buffer_is_empty(content_type))
		{
			/* we are setting application/octet-stream, but also announce that
			 * this header field might change in the seconds few requests
			 *
			 * This should fix the aggressive caching of FF and the script download
			 * seen by the first installations
			 */

			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"),
					CONST_STR_LEN("application/octet-stream")) ;
		}
		else
		{
			response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"),
					CONST_BUF_LEN(content_type)) ;
		}
	}
	/* prepare header */
	if (NULL == (ds = (data_string *) array_get_element(con->response.headers,
			"Last-Modified")))
	{
		mtime = strftime_cache_get(srv, file_info.create_timestamp);
		response_header_overwrite(srv, con, CONST_STR_LEN("Last-Modified"),
				CONST_BUF_LEN(mtime)) ;
	}
	else
	{
		mtime = ds->value;
	}

	if (NULL == array_get_element(con->response.headers, "ETag"))
	{
		/* generate e-tag */
		buffer *file_etag = buffer_init();
		buffer_append_long(file_etag, file_info.file_size);
		buffer_append_string_buffer(file_etag, mtime);
		etag_mutate(con->physical.etag, file_etag);
		buffer_free(file_etag);
		response_header_overwrite(srv, con, CONST_STR_LEN("ETag"),
					CONST_BUF_LEN(con->physical.etag)) ;
	}
	if (HANDLER_FINISHED == http_response_handle_cachable(srv, con, mtime))
	{
		buffer_free(content_type);
		buffer_reset(con->physical.path);
		buffer_free(orgial_path);
		buffer_free(file_hw);
		buffer_free(img_content);
		buffer_free(file_ext);
		return HANDLER_FINISHED;
	}

	if (con->request.http_range && con->conf.range_requests)
	{
		int do_range_request = 1;
		/* check if we have a conditional GET */

		if (NULL != (ds = (data_string *) array_get_element(
				con->request.headers, "If-Range")))
		{
			/* if the value is the same as our ETag, we do a Range-request,
			 * otherwise a full 200 */

			if (ds->value->ptr[0] == '"')
			{
				/**
				 * client wants a ETag
				 */
				if (!con->physical.etag)
				{
					do_range_request = 0;
				}
				else if (!buffer_is_equal(ds->value, con->physical.etag))
				{
					do_range_request = 0;
				}
			}
			else if (!mtime)
			{
				/**
				 * we don't have a Last-Modified and can match the If-Range:
				 *
				 * sending all
				 */
				do_range_request = 0;
			}
			else if (!buffer_is_equal(ds->value, mtime))
			{
				do_range_request = 0;
			}
		}

		if (do_range_request)
		{
			/* content prepared, I'm done */
			con->file_finished = 1;

			if (0 == http_response_parse_range(srv, con, p, img_content))
			{
				con->http_status = 206;
			}
			buffer_free(content_type);
			buffer_reset(con->physical.path);
			buffer_free(orgial_path);
			buffer_free(file_hw);
			buffer_free(img_content);
			buffer_free(file_ext);
			return HANDLER_FINISHED;
		}
	}
	buffer_free(content_type);
	chunkqueue_append_buffer(con->write_queue, img_content);
	buffer_reset(con->physical.path);
	buffer_free(orgial_path);
	buffer_free(file_hw);
	buffer_free(img_content);
	buffer_free(file_ext);
	con->file_finished = 1;
	con->mode = DIRECT;
	return HANDLER_FINISHED;
}

#undef EXITFUNC

int mod_fastdfs_plugin_init(plugin *p);
int mod_fastdfs_plugin_init(plugin *p)
{
	p->version = LIGHTTPD_VERSION_ID;
	p->name = buffer_init_string("fastdfs");

	p->init = mod_fastdfs_init;
	p->handle_physical = mod_fastdfs_physical_handler;
	p->handle_subrequest = mod_fastdfs_subrequest;
	;
	p->set_defaults = mod_fastdfs_set_defaults;
	p->cleanup = mod_fastdfs_free;

	p->data = NULL;

	return 0;
}


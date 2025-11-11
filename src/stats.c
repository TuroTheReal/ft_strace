#include "ft_strace.h"

void init_stats(t_tracer *tracer)
{
	tracer->stats_capacity = 512;
	tracer->stats_count = 0;
	tracer->stats = calloc(tracer->stats_capacity, sizeof(t_syscall_stats));
}

void update_stats(t_tracer *tracer, t_syscall_info *info)
{
	int i;
	double elapsed;
	const char *name = info->name ? info->name : "unknown";

	elapsed = (info->end_time.tv_sec - info->start_time.tv_sec) +
			  (info->end_time.tv_usec - info->start_time.tv_usec) / 1000000.0;

	for (i = 0; i < tracer->stats_count; i++) {
		if (strcmp(tracer->stats[i].name, name) == 0) {
			tracer->stats[i].count++;
			tracer->stats[i].total_time += elapsed;
			if (info->ret_val < 0 && info->ret_val >= -4095) {
				tracer->stats[i].errors++;
			}
			return;
		}
	}

	if (tracer->stats_count >= tracer->stats_capacity) {
		tracer->stats_capacity *= 2;
		tracer->stats = realloc(tracer->stats,
								tracer->stats_capacity * sizeof(t_syscall_stats));
	}

	tracer->stats[tracer->stats_count].name = name;
	tracer->stats[tracer->stats_count].count = 1;
	tracer->stats[tracer->stats_count].total_time = elapsed;
	tracer->stats[tracer->stats_count].errors =
		(info->ret_val < 0 && info->ret_val >= -4095) ? 1 : 0;
	tracer->stats_count++;
}

int compare_stats(const void *a, const void *b)
{
	const t_syscall_stats *sa = (const t_syscall_stats *)a;
	const t_syscall_stats *sb = (const t_syscall_stats *)b;

	if (sb->total_time > sa->total_time)
		return 1;
	if (sb->total_time < sa->total_time)
		return -1;
	return 0;
}

void print_stats(t_tracer *tracer)
{
	int i;
	long total_calls = 0;
	double total_time = 0;
	long total_errors = 0;

	qsort(tracer->stats, tracer->stats_count, sizeof(t_syscall_stats), compare_stats);

	for (i = 0; i < tracer->stats_count; i++) {
		total_calls += tracer->stats[i].count;
		total_time += tracer->stats[i].total_time;
		total_errors += tracer->stats[i].errors;
	}

	fprintf(stderr, "%% time     seconds  usecs/call     calls    errors syscall\n");
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");

	for (i = 0; i < tracer->stats_count; i++) {
		double percent = (total_time > 0) ?
						 (tracer->stats[i].total_time / total_time * 100) : 0;
		long usecs_per_call = (tracer->stats[i].count > 0) ?
							  (long)(tracer->stats[i].total_time * 1000000 / tracer->stats[i].count) : 0;

		fprintf(stderr, "%6.2f %11.6f %11ld %9ld ",
				percent,
				tracer->stats[i].total_time,
				usecs_per_call,
				tracer->stats[i].count);

		if (tracer->stats[i].errors > 0) {
			fprintf(stderr, "%9ld ", tracer->stats[i].errors);
		} else {
			fprintf(stderr, "          ");
		}

		fprintf(stderr, "%s\n", tracer->stats[i].name);
	}

	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	fprintf(stderr, "100.00 %11.6f             %9ld %9ld total\n",
			total_time, total_calls, total_errors);
}

void free_stats(t_tracer *tracer)
{
	if (tracer->stats) {
		free(tracer->stats);
		tracer->stats = NULL;
	}
}

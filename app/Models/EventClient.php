<?php

namespace App\Models;

use App\Enums\AttendanceStatus;
use Database\Factories\EventClientFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\Pivot;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * A client's booking on an event, with their attendance status.
 * A client can be booked on an event only once.
 */
class EventClient extends Pivot
{
    /** @use HasFactory<EventClientFactory> */
    use HasFactory;

    /**
     * @var bool
     */
    public $incrementing = true;

    /**
     * @var bool
     */
    public $timestamps = false;

    /**
     * Exercises attached to the same client on their other events. Not stored:
     * filled by loadExercisesDoneElsewhere() for the event window.
     *
     * @var list<int>
     */
    public array $exerciseIdsDoneElsewhere = [];

    /**
     * @var array<string, mixed>
     */
    protected $attributes = [
        'status' => 'booked',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => AttendanceStatus::class,
        ];
    }

    /**
     * @return BelongsTo<Event, $this>
     */
    public function event(): BelongsTo
    {
        return $this->belongsTo(Event::class);
    }

    /**
     * The client, deleted ones included: a deleted client stays in the history of the event.
     *
     * @return BelongsTo<Client, $this>
     */
    public function client(): BelongsTo
    {
        return $this->belongsTo(Client::class)->withTrashed();
    }

    /**
     * The exercises attached to the client on this event.
     *
     * @return BelongsToMany<Exercise, $this>
     */
    public function exercises(): BelongsToMany
    {
        return $this->belongsToMany(Exercise::class, 'event_client_exercise', 'event_client_id', 'exercise_id')->orderBy('exercises.sort_order')->orderBy('exercises.id');
    }

    /**
     * Fills `exerciseIdsDoneElsewhere` of every booking with the exercises attached to the
     * same client on their other events, in one query.
     *
     * @param  Collection<int, EventClient>  $bookings
     */
    public static function loadExercisesDoneElsewhere(Collection $bookings): void
    {
        if ($bookings->isEmpty()) {
            return;
        }

        $attached = DB::table('event_client_exercise')
            ->join('event_client', 'event_client.id', '=', 'event_client_exercise.event_client_id')
            ->whereIn('event_client.client_id', $bookings->pluck('client_id')->unique())
            ->select('event_client.id as booking_id', 'event_client.client_id', 'event_client_exercise.exercise_id')
            ->get();

        foreach ($bookings as $booking) {
            $booking->exerciseIdsDoneElsewhere = $attached
                ->where('client_id', $booking->client_id)
                ->where('booking_id', '!=', $booking->id)
                ->pluck('exercise_id')
                ->map(fn (int|string $id): int => (int) $id)
                ->unique()
                ->values()
                ->all();
        }
    }
}

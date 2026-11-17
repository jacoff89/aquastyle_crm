<?php

namespace App\Http\Controllers;

use App\Enums\CommunicationChannel;
use App\Http\Resources\CalendarCommunicationResource;
use App\Models\Communication;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Communications for the period the communications calendar shows: every one whose
 * time falls on the days from `start` to `end`, both inclusive. Narrowed to one author
 * with `creator_id` and to one channel with `channel`.
 *
 * Communications of deleted clients are left out: their card can't be opened from the calendar.
 */
class CommunicationCalendarEventController extends Controller
{
    private const MAX_DAYS = 62;

    public function __invoke(Request $request): AnonymousResourceCollection
    {
        Gate::authorize('viewAny', Communication::class);

        $validated = $request->validate([
            'start' => ['required', 'date_format:Y-m-d'],
            'end' => ['required', 'date_format:Y-m-d', 'after_or_equal:start'],
            'creator_id' => ['nullable', 'integer', Rule::exists(User::class, 'id')],
            'channel' => ['nullable', Rule::enum(CommunicationChannel::class)],
        ]);

        $start = Carbon::createFromFormat('Y-m-d', $validated['start'])->startOfDay();
        $end = Carbon::createFromFormat('Y-m-d', $validated['end'])->addDay()->startOfDay();

        if ($start->diffInDays($end) > self::MAX_DAYS) {
            abort(422, 'Слишком большой период.');
        }

        $communications = Communication::query()
            ->with(['client', 'creator'])
            ->whereHas('client')
            ->occurredBetween($start, $end)
            ->when($request->filled('creator_id'), fn (Builder $query) => $query->where('created_by', $request->integer('creator_id')))
            ->when($request->filled('channel'), fn (Builder $query) => $query->where('channel', $request->enum('channel', CommunicationChannel::class)))
            ->orderBy('occurred_at')
            ->orderBy('id')
            ->get();

        return CalendarCommunicationResource::collection($communications);
    }
}

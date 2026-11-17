<?php

namespace App\Http\Controllers;

use App\Enums\CommunicationChannel;
use App\Enums\CommunicationStatus;
use App\Models\Communication;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The calendar of communications with clients, for administrators. Communications
 * themselves are loaded separately, for the visible period only (see
 * CommunicationCalendarEventController). Like the event calendar, the page opens on
 * the day, view and filters (`creator_id`, `channel`, `status`) given in the address.
 */
class CommunicationCalendarController extends Controller
{
    use ReadsCalendarQuery;

    public function __invoke(Request $request): Response
    {
        Gate::authorize('viewAny', Communication::class);

        $channel = CommunicationChannel::tryFrom((string) $request->query('channel'));
        $status = CommunicationStatus::tryFrom((string) $request->query('status'));

        return Inertia::render('communications/Index', [
            'initialDate' => $this->requestedDate($request->query('date')),
            'initialView' => $this->requestedView($request->query('view')),
            'initialFilters' => [
                'creatorId' => $this->requestedId($request->query('creator_id'), User::query()),
                'channel' => $channel?->value,
                'status' => $status?->value,
            ],
            'creators' => User::query()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (User $user): array => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'isActive' => $user->is_active,
                ]),
            'channels' => CommunicationChannel::options(),
            'statuses' => CommunicationStatus::options(),
        ]);
    }
}

<?php

namespace App\Http\Controllers;

use App\Models\Notice;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The notifications page. Administrators see every notice, everyone else the ones that concern them.
 * Opening a notice marks it as read and leads to the page of the change.
 */
class NoticeController extends Controller
{
    private const PER_PAGE = 30;

    public function index(Request $request): Response
    {
        $user = $request->user();
        $onlyUnread = $request->query('filter') === 'unread';

        $notices = Notice::query()
            ->visibleTo($user)
            ->when($onlyUnread, fn ($query) => $query->unreadBy($user))
            ->with('actor')
            ->withExists(['readers as is_read' => fn ($readers) => $readers->whereKey($user->getKey())])
            ->latest('created_at')
            ->latest('id')
            ->paginate(self::PER_PAGE)
            ->withQueryString();

        return Inertia::render('notifications/Index', [
            'notices' => [
                'data' => $notices->getCollection()->map(fn (Notice $notice): array => $this->row($notice, $user))->values(),
                'currentPage' => $notices->currentPage(),
                'lastPage' => $notices->lastPage(),
                'total' => $notices->total(),
                'previousPageUrl' => $notices->previousPageUrl(),
                'nextPageUrl' => $notices->nextPageUrl(),
            ],
            'filter' => $onlyUnread ? 'unread' : 'all',
            'hasUnread' => Notice::query()->visibleTo($user)->unreadBy($user)->exists(),
        ]);
    }

    /**
     * Mark the notice as read and go to the page of the change, or back to the list when it has none.
     */
    public function open(Request $request, Notice $notice): RedirectResponse
    {
        Gate::authorize('view', $notice);

        $notice->markAsReadBy($request->user());

        $url = $notice->urlFor($request->user());

        return $url === null ? back() : redirect($url);
    }

    public function readAll(Request $request): RedirectResponse
    {
        Notice::markAllAsReadBy($request->user());

        return back();
    }

    /**
     * @return array{id: int, message: string, actorName: ?string, createdAtLabel: string, isRead: bool, hasLink: bool}
     */
    private function row(Notice $notice, User $user): array
    {
        return [
            'id' => $notice->id,
            'message' => $notice->message,
            'actorName' => $notice->actor?->fullName(),
            'createdAtLabel' => $notice->created_at->format('d.m.Y H:i'),
            'isRead' => (bool) $notice->is_read,
            'hasLink' => $notice->urlFor($user) !== null,
        ];
    }
}

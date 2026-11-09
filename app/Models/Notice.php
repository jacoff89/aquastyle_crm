<?php

namespace App\Models;

use App\Enums\NoticeType;
use App\Enums\TelegramNoticeScope;
use Database\Factories\NoticeFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\DB;

/**
 * A notification in the CRM: one per domain event, written by the CreateNotice listener.
 * It is called a notice in the code, so that it does not clash with Laravel's notifications
 * (the password reset mail is one of them).
 *
 * Administrators see every notice. Anyone else sees only the notices that concern them:
 * the users in `recipients`, e.g. the instructors of a rescheduled event.
 * Whether a user has read a notice is kept per user in `readers`; the author of the change
 * gets it already read.
 *
 * Users who linked Telegram also get the notices of the types they chose there
 * (see telegramRecipients()).
 *
 * Notices are not domain data, so creating or reading them announces no domain event.
 */
#[Fillable(['type', 'message', 'url', 'url_for_concerned', 'actor_id', 'data', 'created_at'])]
class Notice extends Model
{
    /** @use HasFactory<NoticeFactory> */
    use HasFactory;

    /**
     * A notice is written once and never edited.
     */
    public const UPDATED_AT = null;

    /**
     * The unread counter in the menu stops at this number and shows "99+".
     */
    public const UNREAD_COUNT_CAP = 100;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'data' => 'array',
            'created_at' => 'datetime',
        ];
    }

    /**
     * The user who made the change; null for a change made from the console.
     *
     * @return BelongsTo<User, $this>
     */
    public function actor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'actor_id');
    }

    /**
     * The users the notice concerns, besides the administrators who see every notice.
     *
     * @return BelongsToMany<User, $this>
     */
    public function recipients(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'notice_recipients');
    }

    /**
     * The users who have read the notice, with `pivot->read_at`.
     *
     * @return BelongsToMany<User, $this>
     */
    public function readers(): BelongsToMany
    {
        return $this->belongsToMany(User::class, 'notice_reads')->withPivot('read_at');
    }

    /**
     * Notices the user may see: all of them for an administrator, the ones that concern them otherwise.
     *
     * @param  Builder<Notice>  $query
     */
    #[Scope]
    protected function visibleTo(Builder $query, User $user): void
    {
        if (! $user->isAdmin()) {
            $query->whereHas('recipients', fn (Builder $recipients) => $recipients->whereKey($user->getKey()));
        }
    }

    /**
     * Notices the user has not read yet.
     *
     * @param  Builder<Notice>  $query
     */
    #[Scope]
    protected function unreadBy(Builder $query, User $user): void
    {
        $query->whereDoesntHave('readers', fn (Builder $readers) => $readers->whereKey($user->getKey()));
    }

    public function isVisibleTo(User $user): bool
    {
        return $user->isAdmin() || $this->recipients()->whereKey($user->getKey())->exists();
    }

    /**
     * Where the notice leads the given user: a concerned user who is not an administrator may get
     * a page of their own instead, e.g. their profile rather than the account settings.
     */
    public function urlFor(User $user): ?string
    {
        if (! $user->isAdmin() && $this->url_for_concerned !== null) {
            return $this->url_for_concerned;
        }

        return $this->url;
    }

    /**
     * The users who get the notice in Telegram: active users with a linked chat who chose its type,
     * either every notice of it (administrators) or the ones that concern them.
     * The author of the change is left out, since they know about it.
     *
     * @return Collection<int, User>
     */
    public function telegramRecipients(): Collection
    {
        $type = NoticeType::tryFrom($this->type);

        if ($type === null) {
            return new Collection;
        }

        $concernedIds = $this->recipients()->pluck('users.id')->map(intval(...))->all();

        return User::query()
            ->whereNotNull('telegram_chat_id')
            ->where('is_active', true)
            ->when($this->actor_id !== null, fn (Builder $users) => $users->whereKeyNot($this->actor_id))
            ->get()
            ->filter(fn (User $user): bool => match ($user->telegramScopeFor($type)) {
                TelegramNoticeScope::All => true,
                TelegramNoticeScope::Mine => in_array($user->id, $concernedIds, true),
                null => false,
            })
            ->values();
    }

    public function markAsReadBy(User $user): void
    {
        $this->readers()->syncWithoutDetaching([$user->getKey() => ['read_at' => now()]]);
    }

    /**
     * Mark every notice the user sees and has not read yet as read, in one query.
     */
    public static function markAllAsReadBy(User $user): void
    {
        DB::table('notice_reads')->insertUsing(
            ['notice_id', 'user_id', 'read_at'],
            static::query()->visibleTo($user)->unreadBy($user)->selectRaw('id, ?, ?', [$user->getKey(), now()]),
        );
    }

    /**
     * How many notices the user has not read, counted up to UNREAD_COUNT_CAP, so that the menu
     * stays cheap for an administrator who never reads them.
     */
    public static function unreadCountFor(User $user): int
    {
        return DB::query()
            ->fromSub(static::query()->visibleTo($user)->unreadBy($user)->select('id')->limit(self::UNREAD_COUNT_CAP), 'unread')
            ->count();
    }
}

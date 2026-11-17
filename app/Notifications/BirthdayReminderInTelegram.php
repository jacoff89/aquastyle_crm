<?php

namespace App\Notifications;

use App\Models\User;
use App\Notifications\Telegram\TelegramChannel;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Notification;
use Illuminate\Queue\Attributes\Backoff;
use Illuminate\Queue\Attributes\Timeout;
use Illuminate\Queue\Attributes\Tries;

/**
 * A reminder in the user's Telegram chat that a colleague's birthday is coming.
 * Each recipient gets their own queued job, as with NoticeInTelegram.
 */
#[Tries(4)]
#[Backoff(10, 60, 300)]
#[Timeout(30)]
class BirthdayReminderInTelegram extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(public User $birthdayPerson, public int $daysLeft) {}

    /**
     * @return list<class-string>
     */
    public function via(object $notifiable): array
    {
        return [TelegramChannel::class];
    }

    /**
     * Skip a user who was deactivated or unlinked Telegram while the reminder waited in the queue.
     */
    public function shouldSend(User $notifiable, string $channel): bool
    {
        return $notifiable->is_active && $notifiable->hasTelegram();
    }

    public function toTelegram(User $notifiable): string
    {
        $when = match ($this->daysLeft) {
            0 => 'сегодня',
            1 => 'завтра',
            default => 'через '.$this->daysLeft.' '.($this->daysLeft < 5 ? 'дня' : 'дней'),
        };

        return '🎂 '.e("{$this->birthdayPerson->fullName()}: день рождения {$when}.");
    }
}

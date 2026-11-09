<?php

namespace App\Notifications;

use App\Models\Notice;
use App\Models\User;
use App\Notifications\Telegram\TelegramChannel;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Notification;
use Illuminate\Queue\Attributes\Backoff;
use Illuminate\Queue\Attributes\Timeout;
use Illuminate\Queue\Attributes\Tries;

/**
 * A notice delivered to the user's Telegram chat. Each recipient gets their own queued job,
 * so a slow or failing chat does not hold up the others and is retried on its own.
 */
#[Tries(4)]
#[Backoff(10, 60, 300)]
#[Timeout(30)]
class NoticeInTelegram extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(public Notice $notice) {}

    /**
     * @return list<class-string>
     */
    public function via(object $notifiable): array
    {
        return [TelegramChannel::class];
    }

    /**
     * Skip a user who was deactivated or unlinked Telegram while the notice waited in the queue.
     */
    public function shouldSend(User $notifiable, string $channel): bool
    {
        return $notifiable->is_active && $notifiable->hasTelegram();
    }

    /**
     * The notice as an HTML message: its text, who made the change and when, and a link to the change.
     */
    public function toTelegram(User $notifiable): string
    {
        $about = implode(' · ', array_filter([
            $this->notice->actor?->fullName(),
            $this->notice->created_at->format('d.m.Y H:i'),
        ]));

        $lines = [e($this->notice->message), '', '<i>'.e($about).'</i>'];
        $url = $this->notice->urlFor($notifiable);

        if ($url !== null) {
            $lines[] = '<a href="'.e($url).'">Открыть в CRM</a>';
        }

        return implode("\n", $lines);
    }
}

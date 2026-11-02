<?php

namespace App\Notifications;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\Attributes\Backoff;
use Illuminate\Queue\Attributes\Timeout;
use Illuminate\Queue\Attributes\Tries;

/**
 * The standard password reset email, sent from the queue so the "forgot password"
 * form answers at once. The payload is encrypted: the jobs table must not hold
 * a working reset token in plain text.
 */
#[Tries(3)]
#[Backoff(30, 120)]
#[Timeout(30)]
class ResetPasswordNotification extends ResetPassword implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;
}
